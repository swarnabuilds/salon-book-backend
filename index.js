import express from 'express';
import cors from 'cors';
import 'dotenv/config'
import { MongoClient } from 'mongodb';
import { ObjectId } from "mongodb";
import { createHmac, timingSafeEqual } from "node:crypto";


const app = express();
const port = process.env.PORT ||  5000;

// Only known client origins may call this API with cookies.
const allowedOrigins = [
  "http://localhost:3000",
  process.env.CLIENT_URL,
  process.env.BETTER_AUTH_URL,
]
  .flatMap((value) => String(value || "").split(","))
  .map((value) => value.trim().replace(/\/$/, ""))
  .filter(Boolean);

app.use(
  cors({
    origin: [...new Set(allowedOrigins)],
    credentials: true,
  })
);
app.use(express.json())

// JWT verification middleware. The Next.js app signs a short-lived HS256
// token with BETTER_AUTH_SECRET; this verifies it before session fallback.
function verifyJwt(req, _res, next) {
  req.jwtUser = null;

  const authHeader = String(req.headers.authorization || "");
  if (!authHeader.startsWith("Bearer ")) return next();

  const token = authHeader.slice(7).trim();
  const secret = String(process.env.BETTER_AUTH_SECRET || "");
  const parts = token.split(".");
  if (!secret || parts.length !== 3) return next();

  const [encodedHeader, encodedPayload, signature] = parts;

  try {
    const header = JSON.parse(
      Buffer.from(encodedHeader, "base64url").toString("utf8")
    );
    if (header.alg !== "HS256") return next();

    const expected = createHmac("sha256", secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest();
    const actual = Buffer.from(signature, "base64url");

    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
      return next();
    }

    const payload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf8")
    );
    if (!payload.exp || payload.exp * 1000 <= Date.now()) return next();

    req.jwtUser = {
      id: payload.sub || payload.id || "",
      email: String(payload.email || "").trim().toLowerCase(),
      role: String(payload.role || "customer"),
      isBlocked: Boolean(payload.isBlocked),
    };
  } catch {
    req.jwtUser = null;
  }

  return next();
}

app.use(verifyJwt);


const client = new MongoClient(process.env.MONGO_URI)
export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}
const connectedClient = await connectToMongoDB();
const db = connectedClient.db("salon-book-system");
const servicesCollection = db.collection("services");
const appointmentsCollection = db.collection("appointments");
const transactionsCollection = db.collection("transactions");
const usersCollection = db.collection("user");

// Better Auth lives in the Next.js app. Ask it who owns the request cookie.
const AUTH_URL = (
  process.env.BETTER_AUTH_URL ||
  process.env.CLIENT_URL ||
  "http://localhost:3000"
).replace(/\/$/, "");

async function getAuthenticatedUser(req) {
  // A verified JWT is preferred when the client sends one. Re-read the user
  // from MongoDB so a newly blocked account loses access immediately.
  if (req.jwtUser) {
    const freshUser = await usersCollection.findOne({
      $or: [
        buildUserIdFilter(req.jwtUser.id),
        { email: req.jwtUser.email },
      ],
    });

    if (freshUser) {
      return {
        ...req.jwtUser,
        role: freshUser.role || req.jwtUser.role,
        isBlocked: Boolean(freshUser.isBlocked),
      };
    }

    return req.jwtUser;
  }

  const cookie = req.headers.cookie;
  if (!cookie) return null;

  const response = await fetch(`${AUTH_URL}/api/auth/get-session`, {
    headers: { cookie },
  });

  if (!response.ok) return null;

  const data = await response.json().catch(() => null);
  return data?.user || null;
}

// Use this on every admin-only API route.
async function requireAdmin(req, res, next) {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to continue.",
      });
    }

    const role = String(user.role || "customer").trim().toLowerCase();

    if (role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin access required.",
      });
    }

    if (Boolean(user.isBlocked)) {
      return res.status(403).json({
        success: false,
        message: "This account is blocked.",
      });
    }

    return next();
  } catch (error) {
    console.error("Admin session verification failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not verify your session.",
    });
  }
}

function buildUserIdFilter(id) {
  const values = [id];

  if (ObjectId.isValid(id)) {
    values.unshift(new ObjectId(id));
  }

  return { _id: { $in: values } };
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function toCustomerResponse(user) {
  return {
    _id: String(user._id),
    name: user.name || "",
    email: user.email || "",
    image: user.image || "",
    role: user.role || "customer",
    isBlocked: Boolean(user.isBlocked),
    emailVerified: Boolean(user.emailVerified),
    createdAt: user.createdAt || null,
    updatedAt: user.updatedAt || null,
  };
}

// Public service payloads must not reveal the admin account that created them.
function toPublicService(service) {
  const { createdBy, createdByEmail, creatorEmail, ...safeService } = service;
  return safeService;
}



// services related api 
// Create a new service using  creator email
app.post("/services", requireAdmin, async (req, res) => {
  try {
    const serviceData = req.body;
    const serviceName = String(
      serviceData.serviceName || serviceData.name || ""
    ).trim();

    // Ensure required fields and creator email are present
    if (!serviceName || !serviceData.category || !serviceData.createdBy) {
      return res.status(400).json({
        success: false,
        message: "Service name, category, and createdBy email are required.",
      });
    }

    // The assignment requires a positive price and duration.
    const priceValue = Number(serviceData.price);
    const durationValue = Number(serviceData.duration);

    if (!Number.isFinite(priceValue) || priceValue <= 0) {
      return res.status(400).json({
        success: false,
        message: "Price must be a positive number.",
      });
    }

    if (!Number.isFinite(durationValue) || durationValue <= 0) {
      return res.status(400).json({
        success: false,
        message: "Duration must be a positive number of minutes.",
      });
    }

    const isActive =
      typeof serviceData.isActive === "boolean"
        ? serviceData.isActive
        : serviceData.status !== "inactive";

    const newService = {
      ...serviceData,
      serviceName,
      price: priceValue,
      duration: durationValue,
      isActive,
      status: isActive ? "active" : "inactive",
      createdBy: String(serviceData.createdBy).trim().toLowerCase(),
      createdAt: new Date(),
    };

    const result = await servicesCollection.insertOne(newService);
    return res.status(201).json({
      success: true,
      message: "Service created successfully.",
      data: toPublicService({
        _id: result.insertedId,
        ...newService,
      }),
    });
  } catch (error) {
    console.error("Error creating service:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to create service.",
    });
  }
});

// Get all active services API
app.get('/services', async (req, res) => {
  try {
    // Get query parameters from the client
    const { category, search, limit, includeInactive } = req.query;

    // Admin screens may ask for inactive services too, so they can be
    // reactivated later. Everyone else only sees active services.
    const wantsInactive = String(includeInactive).toLowerCase() === "true";

    if (wantsInactive) {
      const user = await getAuthenticatedUser(req);

      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Please sign in to continue.",
        });
      }

      if (Boolean(user.isBlocked)) {
        return res.status(403).json({
          success: false,
          message: "This account is blocked.",
        });
      }

      const role = String(user.role || "").trim().toLowerCase();
      if (role !== "admin") {
        return res.status(403).json({
          success: false,
          message: "Admin access required.",
        });
      }
    }

    // Legacy "inactive" status records must never appear on public pages.
    let query = wantsInactive
      ? {}
      : { isActive: true, status: { $ne: "inactive" } };

    // Filter services by category if a category is provided
    // Skip category filtering when the category is "All"
    if (category && category !== 'All') {
      query.category = category;
    }

    // Search services by serviceName if a search value is provided
    if (search) {
      const safeSearch = escapeRegex(String(search).trim().slice(0, 100));
      if (safeSearch) {
        query.serviceName = {
          $regex: safeSearch,
          $options: 'i'
        };
      }
    }

    // Find services based on the query
    // Newest services will appear first
    let cursor = servicesCollection
      .find(query)
      .sort({ createdAt: -1 });

    // Limit the number of returned services if a limit is provided
    if (limit) {
      cursor = cursor.limit(Number(limit));
    }

    const services = await cursor.toArray();
    const visibleServices = services.map(toPublicService);

    res.status(200).json({
      success: true,
      count: visibleServices.length,
      data: visibleServices,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Fetch a single salon service by ID (details)
app.get("/services/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Validate MongoDB ObjectId format before querying
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service ID format.",
      });
    }

    const service = await servicesCollection.findOne({ _id: new ObjectId(id) });
    if (!service) {
      return res.status(404).json({
        success: false,
        message: "Service not found.",
      });
    }

    const user = await getAuthenticatedUser(req);
    const isAdmin =
      user &&
      !Boolean(user.isBlocked) &&
      String(user.role || "").trim().toLowerCase() === "admin";
    const isActive = service.isActive !== false && service.status !== "inactive";

    // Inactive services are only visible to a signed-in, unblocked admin.
    if (!isActive && !isAdmin) {
      return res.status(404).json({
        success: false,
        message: "Service not found.",
      });
    }

    return res.status(200).json({
      success: true,
      // Admin account details stored on a service are never exposed.
      data: toPublicService(service),
    });
  } catch (error) {
    console.error("Error fetching service by ID:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch service details.",
    });
  }
});

// Delete a salon service by ID
app.delete("/services/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Validate MongoDB ObjectId format
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service ID format.",
      });
    }

    const result = await servicesCollection.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Service not found.",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Service deleted successfully.",
      deletedId: id,
    });
  } catch (error) {
    console.error("Error deleting service:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to delete service.",
    });
  }
});

// Update an existing salon service by ID
app.patch("/services/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Validate MongoDB ObjectId format
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service ID format.",
      });
    }

    // Prevent overwriting _id or createdAt accidentally
    const { _id, createdAt, ...updateFields } = req.body;

    const cleanUpdate = {
      ...updateFields,
      updatedAt: new Date(),
    };

    if (typeof cleanUpdate.serviceName === "string") {
      cleanUpdate.serviceName = cleanUpdate.serviceName.trim();
      if (!cleanUpdate.serviceName) {
        return res.status(400).json({
          success: false,
          message: "Service name cannot be empty.",
        });
      }
    }

    if (cleanUpdate.price !== undefined) {
      const priceValue = Number(cleanUpdate.price);

      if (!Number.isFinite(priceValue) || priceValue <= 0) {
        return res.status(400).json({
          success: false,
          message: "Price must be a positive number.",
        });
      }

      cleanUpdate.price = priceValue;
    }

    if (cleanUpdate.duration !== undefined) {
      const durationValue = Number(cleanUpdate.duration);

      if (!Number.isFinite(durationValue) || durationValue <= 0) {
        return res.status(400).json({
          success: false,
          message: "Duration must be a positive number of minutes.",
        });
      }

      cleanUpdate.duration = durationValue;
    }

    // Keep the active flag and the legacy status field in sync.
    if (cleanUpdate.isActive !== undefined) {
      cleanUpdate.isActive = Boolean(cleanUpdate.isActive);
      cleanUpdate.status = cleanUpdate.isActive ? "active" : "inactive";
    }

    if (typeof cleanUpdate.createdBy === "string") {
      cleanUpdate.createdBy = cleanUpdate.createdBy.trim().toLowerCase();
    }

    const result = await servicesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: cleanUpdate }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Service not found.",
      });
    }

    const updatedService = await servicesCollection.findOne({
      _id: new ObjectId(id),
    });

    return res.status(200).json({
      success: true,
      message: "Service updated successfully.",
      data: updatedService ? toPublicService(updatedService) : null,
    });
  } catch (error) {
    console.error("Error updating service:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to update service.",
    });
  }
});


// appointments api
// Create a new appointment booking

app.post("/appointments", async (req, res) => {
  try {
    const { serviceId, appointmentDate, timeSlot, message } = req.body;

    // Only authenticated customers can book appointments. The role and the
    // customer identity come from the verified session, never from the body.
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to book an appointment.",
      });
    }

    if (Boolean(user.isBlocked)) {
      return res.status(403).json({
        success: false,
        message: "This account is blocked.",
      });
    }

    const normalizedRole = String(user.role || "customer")
      .trim()
      .toLowerCase();

    if (normalizedRole !== "customer") {
      return res.status(403).json({
        success: false,
        message: "Only customers can book appointments.",
      });
    }

    if (!serviceId || !appointmentDate || !timeSlot) {
      return res.status(400).json({
        success: false,
        message: "Required fields are missing.",
      });
    }

    // Find the requested service
    const service = ObjectId.isValid(serviceId)
      ? await servicesCollection.findOne({ _id: new ObjectId(serviceId) })
      : null;

    if (!service) {
      return res.status(404).json({
        success: false,
        message: "Service not found.",
      });
    }

    // Check active status supporting both isActive and status fields
    const isActive = service.isActive !== false && service.status !== "inactive";
    if (!isActive) {
      return res.status(400).json({
        success: false,
        message: "This service is currently inactive.",
      });
    }

    // Check for an existing booking in the same time slot
    const existingBooking = await appointmentsCollection.findOne({
      serviceId,
      appointmentDate: String(appointmentDate).trim(),
      timeSlot: String(timeSlot).trim(),
      status: { $in: ["pending", "confirmed"] },
    });

    if (existingBooking) {
      return res.status(409).json({
        success: false,
        message: "This time slot is already booked.",
      });
    }

    // Create the appointment
    const appointment = {
      serviceId,
      customerId: String(user.id || user._id || ""),
      customerName: String(user.name || "").trim(),
      customerEmail: String(user.email || "")
        .trim()
        .toLowerCase(),
      serviceName: service.serviceName,
      appointmentDate: String(appointmentDate).trim(),
      timeSlot: String(timeSlot).trim(),
      message: String(message || "").trim(),
      servicePrice: service.price,
      status: "pending",
      paymentStatus: "unpaid",
      createdAt: new Date(),
    };

    const result = await appointmentsCollection.insertOne(appointment);

    return res.status(201).json({
      success: true,
      message: "Appointment booked successfully.",
      data: { _id: result.insertedId, ...appointment },
    });
  } catch (error) {
    console.error("Appointment booking error:", error);
    return res.status(500).json({
      success: false,
      message: "Server error.",
    });
  }
});


// Get appointments. Customers only ever receive their own records; admins
// receive every appointment.
app.get("/appointments", async (req, res) => {
  try {
    const { email, status } = req.query;

    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to view appointments.",
      });
    }

    if (Boolean(user.isBlocked)) {
      return res.status(403).json({
        success: false,
        message: "This account is blocked.",
      });
    }

    const role = String(user.role || "customer").trim().toLowerCase();
    const query = {};

    if (role === "admin") {
      // Admins may optionally filter by a customer email.
      if (email) {
        query.customerEmail = String(email).trim().toLowerCase();
      }
    } else {
      // Customers can only view their own appointments. The email query value
      // is deliberately ignored so one customer cannot read another's data.
      query.customerEmail = String(user.email || "").trim().toLowerCase();
    }

    if (status && status !== "all") {
      query.status = String(status).trim().toLowerCase();
    }

    const appointments = await appointmentsCollection
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();

    const enrichedAppointments = await Promise.all(
      appointments.map(async (item) => {
        let serviceImage = item.serviceImage || item.image || "";
        let serviceCategory = item.serviceCategory || item.category || "";

        if (
          (!serviceImage || !serviceCategory) &&
          item.serviceId &&
          ObjectId.isValid(item.serviceId)
        ) {
          const srv = await servicesCollection.findOne({
            _id: new ObjectId(item.serviceId),
          });
          if (srv) {
            serviceImage = serviceImage || srv.image || "";
            serviceCategory = serviceCategory || srv.category || "";
          }
        }

        // Attach the customer's profile image from the Better Auth user
        let customerImage = item.customerImage || "";

        if (!customerImage && item.customerEmail) {
          const customer = await usersCollection.findOne({
            email: String(item.customerEmail).trim().toLowerCase(),
          });
          customerImage = customer?.image || "";
        }

        return {
          ...item,
          serviceImage,
          serviceCategory,
          customerImage,
        };
      })
    );

    return res.status(200).json({
      success: true,
      data: enrichedAppointments,
    });
  } catch (error) {
    console.error("Fetch appointments error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch appointments.",
    });
  }
});

// Get a single appointment. Used by the checkout flow to verify that the
// appointment exists, belongs to the signed-in customer, is confirmed, and is
// still unpaid before a Stripe session is created.
app.get("/appointments/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid appointment ID.",
      });
    }

    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to view this appointment.",
      });
    }

    if (Boolean(user.isBlocked)) {
      return res.status(403).json({
        success: false,
        message: "This account is blocked.",
      });
    }

    const appointment = await appointmentsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!appointment) {
      return res.status(404).json({
        success: false,
        message: "Appointment not found.",
      });
    }

    const role = String(user.role || "customer").trim().toLowerCase();
    const isOwner =
      String(user.email || "").trim().toLowerCase() ===
      String(appointment.customerEmail || "").trim().toLowerCase();

    // Customers may only read their own appointment; admins may read any.
    if (role !== "admin" && !isOwner) {
      return res.status(403).json({
        success: false,
        message: "You can only view your own appointments.",
      });
    }

    let serviceImage = appointment.serviceImage || appointment.image || "";
    let serviceCategory =
      appointment.serviceCategory || appointment.category || "";

    if (
      (!serviceImage || !serviceCategory) &&
      appointment.serviceId &&
      ObjectId.isValid(appointment.serviceId)
    ) {
      const srv = await servicesCollection.findOne({
        _id: new ObjectId(appointment.serviceId),
      });
      if (srv) {
        serviceImage = serviceImage || srv.image || "";
        serviceCategory = serviceCategory || srv.category || "";
      }
    }

    return res.status(200).json({
      success: true,
      data: {
        ...appointment,
        serviceImage,
        serviceCategory,
      },
    });
  } catch (error) {
    console.error("Fetch single appointment error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch the appointment.",
    });
  }
});

// Update appointment status (confirmed, completed, cancelled)
app.patch("/appointments/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, paymentStatus, stripeSessionId, amount, currency } = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid appointment ID.",
      });
    }

    const existing = await appointmentsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!existing) {
      return res.status(404).json({
        success: false,
        message: "Appointment not found.",
      });
    }

    const currentPaymentStatus = String(
      existing.paymentStatus || "unpaid"
    ).toLowerCase();

    // Prevent updating payment status if already paid
    if (paymentStatus && currentPaymentStatus === "paid") {
      return res.status(400).json({
        success: false,
        message: "This appointment is already paid.",
      });
    }

    // Handle payment status update after successful Stripe checkout
    if (paymentStatus) {
      // Only the verified server-side Stripe success flow may mark a payment
      // as paid. A browser request cannot fake a successful payment.
      const internalSecret = String(req.headers["x-internal-secret"] || "");
      const expectedSecret = String(process.env.BETTER_AUTH_SECRET || "");

      if (!expectedSecret || internalSecret !== expectedSecret) {
        return res.status(403).json({
          success: false,
          message:
            "Payment status can only be updated after a verified Stripe payment.",
        });
      }

      const normalizedPayment = String(paymentStatus).trim().toLowerCase();
      if (!["paid", "unpaid"].includes(normalizedPayment)) {
        return res.status(400).json({
          success: false,
          message: "Invalid payment status.",
        });
      }

      const cleanSessionId = String(stripeSessionId || "").trim();
      const paymentAmount = Number(amount ?? existing.servicePrice ?? 0);

      if (normalizedPayment === "paid") {
        if (!cleanSessionId) {
          return res.status(400).json({
            success: false,
            message: "A Stripe checkout session ID is required.",
          });
        }

        if (!Number.isFinite(paymentAmount) || paymentAmount <= 0) {
          return res.status(400).json({
            success: false,
            message: "A positive payment amount is required.",
          });
        }

        if (String(existing.status || "").trim().toLowerCase() !== "confirmed") {
          return res.status(400).json({
            success: false,
            message: "Only confirmed appointments can be paid.",
          });
        }
      }

      await appointmentsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            paymentStatus: normalizedPayment,
            ...(cleanSessionId ? { stripeSessionId: cleanSessionId } : {}),
            ...(normalizedPayment === "paid" ? { paidAt: new Date() } : {}),
            updatedAt: new Date(),
          },
        }
      );

      // Save transaction record in transactionsCollection when payment is paid
      if (normalizedPayment === "paid") {
        const existingTx = await transactionsCollection.findOne({
          appointmentId: String(id),
          status: "paid",
        });

        if (!existingTx) {
          await transactionsCollection.insertOne({
            appointmentId: String(id),
            customerId: existing.customerId || existing.customerEmail || "",
            customerName: existing.customerName || "Customer",
            customerEmail: existing.customerEmail || "",
            serviceName: existing.serviceName || "Salon Service",
            appointmentDate: existing.appointmentDate || "",
            amount: paymentAmount,
            currency: String(currency || "USD").toUpperCase(),
            stripeSessionId: cleanSessionId,
            status: "paid",
            createdAt: new Date(),
          });
        }
      }

      return res.status(200).json({
        success: true,
        message: `Payment marked as ${normalizedPayment}.`,
      });
    }

    // Handle booking status update (confirmed or cancelled only)
    const nextStatus = String(status || "").trim().toLowerCase();
    const allowedStatuses = ["confirmed", "cancelled"];

    if (!allowedStatuses.includes(nextStatus)) {
      return res.status(400).json({
        success: false,
        message: "Unsupported update operation.",
      });
    }

    const currentStatus = String(existing.status || "pending").toLowerCase();

    const authenticatedUser = await getAuthenticatedUser(req);

    if (!authenticatedUser) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to update this appointment.",
      });
    }

    if (Boolean(authenticatedUser.isBlocked)) {
      return res.status(403).json({
        success: false,
        message: "This account is blocked.",
      });
    }

    const isAdmin =
      String(authenticatedUser.role || "").trim().toLowerCase() === "admin";
    const isOwner =
      String(authenticatedUser.email || "").trim().toLowerCase() ===
      String(existing.customerEmail || "").trim().toLowerCase();

    // Only pending appointments can be confirmed, and only by an admin.
    if (nextStatus === "confirmed") {
      if (!isAdmin) {
        return res.status(403).json({
          success: false,
          message: "Only an admin can confirm appointments.",
        });
      }

      if (currentStatus !== "pending") {
        return res.status(400).json({
          success: false,
          message: "Only pending appointments can be confirmed.",
        });
      }
    }

    if (nextStatus === "cancelled") {
      const canCancel = isAdmin
        ? currentStatus === "pending" || currentStatus === "confirmed"
        : isOwner && currentStatus === "pending";

      if (!canCancel) {
        return res.status(400).json({
          success: false,
          message: isOwner
            ? `Cannot cancel an already ${currentStatus} appointment.`
            : "You can only cancel your own pending appointments.",
        });
      }
    }

    await appointmentsCollection.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          status: nextStatus,
          updatedAt: new Date(),
        },
      }
    );

    return res.status(200).json({
      success: true,
      message: `Appointment ${nextStatus} successfully.`,
    });
  } catch (error) {
    console.error("PATCH /appointments/:id error:", error);
    return res.status(500).json({
      success: false,
      message: "Server error while updating appointment.",
    });
  }
});


// GET all payment transactions for Admin Dashboard
app.get("/transactions", requireAdmin, async (req, res) => {
  try {
    const transactions = await transactionsCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    // Attach the customer's profile image for the admin ledger.
    const enrichedTransactions = await Promise.all(
      transactions.map(async (item) => {
        let customerImage = item.customerImage || "";

        if (!customerImage && item.customerEmail) {
          const customer = await usersCollection.findOne({
            email: String(item.customerEmail).trim().toLowerCase(),
          });
          customerImage = customer?.image || "";
        }

        return { ...item, customerImage };
      })
    );

    return res.status(200).json({
      success: true,
      data: enrichedTransactions,
    });
  } catch (error) {
    console.error("GET /transactions error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to load transactions.",
    });
  }
});


// Admin: list registered customers. Other admins are never returned, even
// if a client tries to request the admin role explicitly.
app.get("/users", requireAdmin, async (req, res) => {
  try {
    const { search, status } = req.query;
    const query = { role: { $ne: "admin" } };

    if (status === "blocked") {
      query.isBlocked = true;
    } else if (status === "active") {
      query.isBlocked = { $ne: true };
    }

    if (search) {
      const safeSearch = escapeRegex(String(search).trim().slice(0, 100));

      if (safeSearch) {
        query.$or = [
          { name: { $regex: safeSearch, $options: "i" } },
          { email: { $regex: safeSearch, $options: "i" } },
        ];
      }
    }

    const customers = await usersCollection
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();

    return res.status(200).json({
      success: true,
      count: customers.length,
      data: customers.map(toCustomerResponse),
    });
  } catch (error) {
    console.error("GET /users error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to load customers.",
    });
  }
});

// Admin: block or unblock a customer
app.patch("/users/:id/block", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { isBlocked } = req.body;

    if (typeof isBlocked !== "boolean") {
      return res.status(400).json({
        success: false,
        message: "isBlocked must be true or false.",
      });
    }

    if (!id) {
      return res.status(400).json({
        success: false,
        message: "User ID is required.",
      });
    }

    const userFilter = buildUserIdFilter(id);
    const user = await usersCollection.findOne(userFilter);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Customer not found.",
      });
    }

    if (String(user.role || "customer").trim().toLowerCase() === "admin") {
      return res.status(400).json({
        success: false,
        message: "Admin accounts cannot be blocked.",
      });
    }

    await usersCollection.updateOne(userFilter, {
      $set: {
        isBlocked,
        updatedAt: new Date(),
      },
    });

    const updatedUser = await usersCollection.findOne(userFilter);

    return res.status(200).json({
      success: true,
      message: isBlocked
        ? "Customer blocked successfully."
        : "Customer unblocked successfully.",
      data: toCustomerResponse(updatedUser || { ...user, isBlocked }),
    });
  } catch (error) {
    console.error("PATCH /users/:id/block error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to update customer status.",
    });
  }
});

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});