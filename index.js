import express from 'express';
import cors from 'cors';
import 'dotenv/config'
import { MongoClient } from 'mongodb';
import { ObjectId } from "mongodb";
import { createHmac, timingSafeEqual } from "node:crypto";


const app = express();
const port = process.env.PORT ||  5000;

// Only known client origins may call this API with cookies. Local development
// uses localhost; production should rely on the configured client URL.
const isProduction = process.env.NODE_ENV === "production";
const allowedOrigins = [
  process.env.CLIENT_URL,
  process.env.BETTER_AUTH_URL,
  ...(isProduction
    ? []
    : [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
      ]),
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

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeRole(value) {
  return String(value || "customer").trim().toLowerCase();
}

async function getAuthenticatedUser(req) {
  // A verified JWT is preferred, but the database remains the source of truth.
  // Token claims alone are never trusted for identity, role, or blocked state.
  if (req.jwtUser) {
    const email = normalizeEmail(req.jwtUser.email);
    const identityQuery = [];

    if (req.jwtUser.id) identityQuery.push(buildUserIdFilter(req.jwtUser.id));
    if (email) identityQuery.push({ email });
    if (!identityQuery.length) return null;

    const freshUser = await usersCollection.findOne({ $or: identityQuery });
    if (!freshUser) return null;

    return {
      id: String(freshUser._id),
      _id: freshUser._id,
      name: freshUser.name || "",
      email: normalizeEmail(freshUser.email),
      role: normalizeRole(freshUser.role || req.jwtUser.role),
      isBlocked: Boolean(freshUser.isBlocked),
    };
  }

  const cookie = req.headers.cookie;
  if (!cookie) return null;

  const response = await fetch(`${AUTH_URL}/api/auth/get-session`, {
    headers: { cookie },
  });

  if (!response.ok) return null;

  const data = await response.json().catch(() => null);
  const sessionUser = data?.user || null;
  if (!sessionUser) return null;

  // Apply the same database freshness check to cookie-based sessions.
  const email = normalizeEmail(sessionUser.email);
  const identityQuery = [];

  if (sessionUser.id) identityQuery.push(buildUserIdFilter(sessionUser.id));
  if (email) identityQuery.push({ email });
  if (!identityQuery.length) return null;

  const freshUser = await usersCollection.findOne({ $or: identityQuery });
  if (!freshUser) return null;

  return {
    id: String(freshUser._id),
    _id: freshUser._id,
    name: freshUser.name || "",
    email: normalizeEmail(freshUser.email),
    role: normalizeRole(freshUser.role || sessionUser.role),
    isBlocked: Boolean(freshUser.isBlocked),
  };
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

    if (normalizeRole(user.role) !== "admin") {
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

    req.authenticatedUser = user;
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

// Appointments store customerId as a string, but older records may use an
// ObjectId or an email. Match all safe forms without trusting client input.
// Shared matcher for id fields that may be stored as a string or ObjectId.
function buildIdValueFilter(id) {
  const values = [String(id)];

  if (ObjectId.isValid(id)) {
    values.unshift(new ObjectId(id));
  }

  return { $in: values };
}

function buildCustomerIdFilter(id) {
  return buildIdValueFilter(id);
}

// Services belong to the admin who created them. Older records may only have
// createdBy, so both the id and email are checked.
function buildAdminServiceFilter(admin) {
  const clauses = [];
  const adminId = String(admin?.id || admin?._id || "").trim();
  const adminEmail = normalizeEmail(admin?.email);

  if (adminId) {
    clauses.push({ createdById: buildIdValueFilter(adminId) });
  }

  if (adminEmail) {
    clauses.push({ createdBy: adminEmail });
  }

  return { $or: clauses.length ? clauses : [{ _id: "__no_admin__" }] };
}

function isServiceOwnedByAdmin(service, admin) {
  const adminId = String(admin?.id || admin?._id || "").trim().toLowerCase();
  const adminEmail = normalizeEmail(admin?.email);
  const ownerId = String(service?.createdById || "")
    .trim()
    .toLowerCase();

  if (adminId && ownerId && adminId === ownerId) return true;
  if (adminEmail && normalizeEmail(service?.createdBy) === adminEmail) return true;

  return false;
}

async function getOwnedServiceIds(admin) {
  const ownedServices = await servicesCollection
    .find(buildAdminServiceFilter(admin))
    .project({ _id: 1 })
    .toArray();

  return ownedServices.map((service) => service._id);
}

// Appointments store the service owner at booking time. The serviceId fallback
// keeps older records visible to the correct admin after this field is added.
async function buildAdminAppointmentFilter(admin) {
  const clauses = [];
  const adminId = String(admin?.id || admin?._id || "").trim();
  const adminEmail = normalizeEmail(admin?.email);
  const ownedServiceIds = await getOwnedServiceIds(admin);

  if (adminEmail) {
    clauses.push({ adminEmail });
    clauses.push({ serviceOwnerEmail: adminEmail });
  }

  if (adminId) {
    clauses.push({ adminId: buildIdValueFilter(adminId) });
    clauses.push({ serviceOwnerId: buildIdValueFilter(adminId) });
  }

  if (ownedServiceIds.length) {
    // Appointments may store serviceId as a string or an ObjectId.
    const serviceIdValues = ownedServiceIds.flatMap((id) => [id, String(id)]);
    clauses.push({ serviceId: { $in: serviceIdValues } });
  }

  return { $or: clauses.length ? clauses : [{ _id: "__no_admin__" }] };
}

async function isAppointmentOwnedByAdmin(appointment, admin) {
  const adminId = String(admin?.id || admin?._id || "").trim().toLowerCase();
  const adminEmail = normalizeEmail(admin?.email);
  const ownerEmail = normalizeEmail(
    appointment?.adminEmail || appointment?.serviceOwnerEmail
  );
  const ownerId = String(appointment?.adminId || appointment?.serviceOwnerId || "")
    .trim()
    .toLowerCase();

  if (adminEmail && ownerEmail && adminEmail === ownerEmail) return true;
  if (adminId && ownerId && adminId === ownerId) return true;

  // Legacy appointments may not have owner fields yet. Check the linked
  // service instead so the correct admin still owns the record.
  if (appointment?.serviceId && ObjectId.isValid(appointment.serviceId)) {
    const service = await servicesCollection.findOne({
      _id: new ObjectId(appointment.serviceId),
    });

    if (service && isServiceOwnedByAdmin(service, admin)) return true;
  }

  return false;
}

// Read the admin identity from the booked service. Used when creating
// appointments and when recording a Stripe transaction.
async function getServiceOwnerInfo(serviceId) {
  if (!serviceId || !ObjectId.isValid(serviceId)) {
    return { adminEmail: "", adminId: "" };
  }

  const service = await servicesCollection.findOne({
    _id: new ObjectId(serviceId),
  });

  return {
    adminEmail: normalizeEmail(service?.createdBy),
    adminId: String(service?.createdById || ""),
  };
}

async function buildAdminTransactionFilter(admin) {
  const clauses = [];
  const adminId = String(admin?.id || admin?._id || "").trim();
  const adminEmail = normalizeEmail(admin?.email);
  const ownedAppointments = await appointmentsCollection
    .find(await buildAdminAppointmentFilter(admin))
    .project({ _id: 1 })
    .toArray();
  const ownedAppointmentIds = ownedAppointments.flatMap((item) => [
    item._id,
    String(item._id),
  ]);

  if (adminEmail) {
    clauses.push({ adminEmail });
    clauses.push({ serviceOwnerEmail: adminEmail });
  }

  if (adminId) {
    clauses.push({ adminId: buildIdValueFilter(adminId) });
    clauses.push({ serviceOwnerId: buildIdValueFilter(adminId) });
  }

  if (ownedAppointmentIds.length) {
    clauses.push({ appointmentId: { $in: ownedAppointmentIds } });
  }

  return { $or: clauses.length ? clauses : [{ _id: "__no_admin__" }] };
}

// Build the query used for every customer-owned collection. Email is kept as
// a fallback for older records, but the stored customerId is checked first.
function buildCustomerOwnershipFilter(user) {
  const clauses = [];
  const id = String(user?.id || user?._id || "").trim();
  const email = normalizeEmail(user?.email);

  if (id) {
    clauses.push({ customerId: buildCustomerIdFilter(id) });
  }

  if (email) {
    clauses.push({ customerEmail: email });
    clauses.push({ customerId: email });
  }

  return { $or: clauses.length ? clauses : [{ _id: "__no_user__" }] };
}

function isAppointmentOwner(user, appointment) {
  const userId = String(user?.id || user?._id || "")
    .trim()
    .toLowerCase();
  const customerId = String(appointment?.customerId || "")
    .trim()
    .toLowerCase();
  const email = normalizeEmail(user?.email);

  if (userId && customerId && userId === customerId) return true;
  if (email && normalizeEmail(appointment?.customerEmail) === email) return true;
  if (email && customerId === email) return true;

  return false;
}

function matchesInternalSecret(provided, expected) {
  if (!provided || !expected) return false;

  const providedBuffer = Buffer.from(String(provided));
  const expectedBuffer = Buffer.from(String(expected));

  return (
    providedBuffer.length === expectedBuffer.length &&
    timingSafeEqual(providedBuffer, expectedBuffer)
  );
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

    if (!serviceName || !serviceData.category) {
      return res.status(400).json({
        success: false,
        message: "Service name and category are required.",
      });
    }

    // The creator is derived from the verified admin session, never from the
    // request body. This prevents one admin from attributing records to another.
    const adminEmail = normalizeEmail(req.authenticatedUser?.email);
    if (!adminEmail) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to continue.",
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

    const {
      createdBy,
      createdById,
      createdByEmail,
      creatorEmail,
      _id,
      ...safeServiceData
    } = serviceData;

    const newService = {
      ...safeServiceData,
      serviceName,
      price: priceValue,
      duration: durationValue,
      isActive,
      status: isActive ? "active" : "inactive",
      // Both owner fields come from the verified session, never the request.
      createdBy: adminEmail,
      createdById: String(req.authenticatedUser.id || req.authenticatedUser._id || ""),
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
    const { category, search, limit, includeInactive, scope } = req.query;

    // Admin screens ask for inactive services and scope=admin. Both require a
    // verified admin and return only that admin's own services.
    const wantsInactive = String(includeInactive).toLowerCase() === "true";
    const wantsAdminScope =
      wantsInactive || String(scope).trim().toLowerCase() === "admin";

    // Legacy "inactive" status records must never appear on public pages.
    let query = wantsInactive
      ? {}
      : { isActive: true, status: { $ne: "inactive" } };

    if (wantsAdminScope) {
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

      if (normalizeRole(user.role) !== "admin") {
        return res.status(403).json({
          success: false,
          message: "Admin access required.",
        });
      }

      Object.assign(query, buildAdminServiceFilter(user));
    }

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

    const isActive = service.isActive !== false && service.status !== "inactive";

    // Active services stay public. Inactive services are admin-only and only
    // the admin who created the service may open them.
    if (!isActive) {
      const user = await getAuthenticatedUser(req);
      const isAdmin =
        user && !Boolean(user.isBlocked) && normalizeRole(user.role) === "admin";

      if (!isAdmin || !isServiceOwnedByAdmin(service, user)) {
        return res.status(404).json({
          success: false,
          message: "Service not found.",
        });
      }
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

    const service = await servicesCollection.findOne({ _id: new ObjectId(id) });

    if (!service) {
      return res.status(404).json({
        success: false,
        message: "Service not found.",
      });
    }

    if (!isServiceOwnedByAdmin(service, req.authenticatedUser)) {
      return res.status(403).json({
        success: false,
        message: "You can only manage services you created.",
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

    const service = await servicesCollection.findOne({ _id: new ObjectId(id) });

    if (!service) {
      return res.status(404).json({
        success: false,
        message: "Service not found.",
      });
    }

    if (!isServiceOwnedByAdmin(service, req.authenticatedUser)) {
      return res.status(403).json({
        success: false,
        message: "You can only manage services you created.",
      });
    }

    // Prevent overwriting identity/audit fields from the client.
    const {
      _id,
      createdAt,
      createdBy,
      createdById,
      createdByEmail,
      creatorEmail,
      ...updateFields
    } = req.body;

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

    // Store the service owner so only that admin can manage this booking.
    const serviceOwner = await getServiceOwnerInfo(serviceId);

    // Create the appointment
    const appointment = {
      serviceId,
      customerId: String(user.id || user._id || ""),
      customerName: String(user.name || "").trim(),
      customerEmail: String(user.email || "")
        .trim()
        .toLowerCase(),
      adminEmail: serviceOwner.adminEmail,
      adminId: serviceOwner.adminId,
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

    const role = normalizeRole(user.role);
    const query = {};

    if (role === "admin") {
      // Admins only see bookings for their own services. They may still
      // optionally filter those bookings by a customer email.
      Object.assign(query, await buildAdminAppointmentFilter(user));

      if (email) {
        query.customerEmail = normalizeEmail(email);
      }
    } else if (role === "customer") {
      // Customers are scoped by their authenticated user id/email. Any email
      // query string sent by the browser is deliberately ignored.
      Object.assign(query, buildCustomerOwnershipFilter(user));
    } else {
      return res.status(403).json({
        success: false,
        message: "You cannot view appointments.",
      });
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

    // Ownership is part of the database query itself. A customer cannot fetch
    // another customer's record, and an admin cannot fetch another admin's
    // booking by changing the URL.
    const query = { _id: new ObjectId(id) };
    const role = normalizeRole(user.role);

    if (role === "customer") {
      Object.assign(query, buildCustomerOwnershipFilter(user));
    } else if (role === "admin") {
      Object.assign(query, await buildAdminAppointmentFilter(user));
    } else {
      return res.status(403).json({
        success: false,
        message: "You cannot view this appointment.",
      });
    }

    const appointment = await appointmentsCollection.findOne(query);

    if (!appointment) {
      return res.status(404).json({
        success: false,
        message: "Appointment not found.",
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

// Update a booking status. Admins may only change appointments tied to their
// own services; customers may only cancel their own pending bookings.
async function updateAppointmentStatusRecord(req, res, existing) {
  try {
    const nextStatus = String(req.body?.status || "").trim().toLowerCase();
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

    const role = normalizeRole(authenticatedUser.role);
    const isAdmin = role === "admin";
    const isCustomer = role === "customer";
    const isOwner = isAppointmentOwner(authenticatedUser, existing);
    const adminOwnsAppointment =
      isAdmin && (await isAppointmentOwnedByAdmin(existing, authenticatedUser));

    if (!isAdmin && !isCustomer) {
      return res.status(403).json({
        success: false,
        message: "You cannot update appointments.",
      });
    }

    if (isAdmin && !adminOwnsAppointment) {
      return res.status(403).json({
        success: false,
        message: "You can only manage appointments for your own services.",
      });
    }

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
      if (!isAdmin && !isOwner) {
        return res.status(403).json({
          success: false,
          message: "You can only cancel your own appointments.",
        });
      }

      const allowedCurrentStatuses = isAdmin
        ? ["pending", "confirmed"]
        : ["pending"];

      if (!allowedCurrentStatuses.includes(currentStatus)) {
        return res.status(400).json({
          success: false,
          message: `Cannot cancel an already ${currentStatus} appointment.`,
        });
      }
    }

    await appointmentsCollection.updateOne(
      { _id: new ObjectId(existing._id) },
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
    console.error("PATCH appointment status error:", error);
    return res.status(500).json({
      success: false,
      message: "Server error while updating appointment status.",
    });
  }
}

// Update payment state or booking status. Payment updates are server-only;
// status updates are checked for admin/customer ownership.
app.patch("/appointments/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { paymentStatus, stripeSessionId, currency } = req.body || {};

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

    // No paymentStatus means this is a normal booking status update.
    if (!paymentStatus) {
      return updateAppointmentStatusRecord(req, res, existing);
    }

    const currentPaymentStatus = String(
      existing.paymentStatus || "unpaid"
    ).toLowerCase();

    if (currentPaymentStatus === "paid") {
      return res.status(400).json({
        success: false,
        message: "This appointment is already paid.",
      });
    }

    // Only the verified server-side Stripe success flow may mark a payment
    // as paid. A browser request cannot fake a successful payment.
    const internalSecret = String(req.headers["x-internal-secret"] || "");
    const expectedSecret = String(process.env.BETTER_AUTH_SECRET || "");

    if (!matchesInternalSecret(internalSecret, expectedSecret)) {
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
    // The amount always comes from the stored service price.
    const paymentAmount = Number(existing.servicePrice || 0);

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

    if (normalizedPayment === "paid") {
      const existingTx = await transactionsCollection.findOne({
        appointmentId: String(id),
        status: "paid",
      });

      if (!existingTx) {
        // Fall back to the linked service for older appointments that were
        // created before owner fields were stored.
        const serviceOwner = await getServiceOwnerInfo(existing.serviceId);

        await transactionsCollection.insertOne({
          appointmentId: String(id),
          customerId: existing.customerId || existing.customerEmail || "",
          customerName: existing.customerName || "Customer",
          customerEmail: existing.customerEmail || "",
          adminEmail: existing.adminEmail || serviceOwner.adminEmail,
          adminId: existing.adminId || serviceOwner.adminId,
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
  } catch (error) {
    console.error("PATCH /appointments/:id error:", error);
    return res.status(500).json({
      success: false,
      message: "Server error while updating appointment.",
    });
  }
});

// Explicit status endpoint used by the admin appointment actions.
app.patch("/appointments/:id/status", async (req, res) => {
  try {
    const { id } = req.params;

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

    return updateAppointmentStatusRecord(req, res, existing);
  } catch (error) {
    console.error("PATCH /appointments/:id/status error:", error);
    return res.status(500).json({
      success: false,
      message: "Server error while updating appointment status.",
    });
  }
});


// Admins see the full ledger; customers only ever see their own payments.
app.get("/transactions", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to view transactions.",
      });
    }

    if (Boolean(user.isBlocked)) {
      return res.status(403).json({
        success: false,
        message: "This account is blocked.",
      });
    }

    const role = normalizeRole(user.role);
    const query = {};

    if (role === "admin") {
      // Admins only see revenue from their own services.
      Object.assign(query, await buildAdminTransactionFilter(user));
    } else if (role === "customer") {
      Object.assign(query, buildCustomerOwnershipFilter(user));
    } else {
      return res.status(403).json({
        success: false,
        message: "You cannot view transactions.",
      });
    }

    const transactions = await transactionsCollection
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();

    const enrichedTransactions = await Promise.all(
      transactions.map(async (item) => {
        let customerImage = item.customerImage || "";

        if (!customerImage && item.customerEmail) {
          const customer = await usersCollection.findOne({
            email: normalizeEmail(item.customerEmail),
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

// Admin overview numbers are calculated from the signed-in admin's own
// services, appointments, and transactions only.
app.get("/admin/overview", requireAdmin, async (req, res) => {
  try {
    const admin = req.authenticatedUser;
    const [services, appointments, transactions] = await Promise.all([
      servicesCollection
        .find(buildAdminServiceFilter(admin))
        .sort({ createdAt: -1 })
        .toArray(),
      appointmentsCollection
        .find(await buildAdminAppointmentFilter(admin))
        .sort({ createdAt: -1 })
        .toArray(),
      transactionsCollection
        .find(await buildAdminTransactionFilter(admin))
        .sort({ createdAt: -1 })
        .toArray(),
    ]);

    const paidTransactions = transactions.filter(
      (item) => String(item.status || "").toLowerCase() === "paid"
    );
    const totalRevenue = paidTransactions.reduce(
      (sum, item) => sum + Number(item.amount || 0),
      0
    );

    const stats = {
      totalServices: services.length,
      activeServices: services.filter(
        (item) => item.isActive !== false && item.status !== "inactive"
      ).length,
      totalAppointments: appointments.length,
      pendingCount: appointments.filter(
        (item) => String(item.status || "pending").toLowerCase() === "pending"
      ).length,
      confirmedCount: appointments.filter(
        (item) => String(item.status || "").toLowerCase() === "confirmed"
      ).length,
      completedCount: appointments.filter(
        (item) => String(item.status || "").toLowerCase() === "completed"
      ).length,
      paidCount: paidTransactions.length,
      totalRevenue,
      currency: paidTransactions[0]?.currency || "usd",
    };

    return res.status(200).json({
      success: true,
      data: {
        stats,
        services: services.map(toPublicService),
        appointments,
        transactions,
      },
    });
  } catch (error) {
    console.error("GET /admin/overview error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to load admin overview.",
    });
  }
});

// Admin: list registered customers. Other admins are never returned, even
// if a client tries to request the admin role explicitly.
app.get("/users", requireAdmin, async (req, res) => {
  try {
    const { search, status } = req.query;

    // Case-insensitive exclusion keeps other admins out of the customer list.
    const query = {
      $and: [{ role: { $not: { $regex: /^admin$/i } } }],
    };

    if (status === "blocked") {
      query.isBlocked = true;
    } else if (status === "active") {
      query.isBlocked = { $ne: true };
    }

    if (search) {
      const safeSearch = escapeRegex(String(search).trim().slice(0, 100));

      if (safeSearch) {
        query.$and.push({
          $or: [
            { name: { $regex: safeSearch, $options: "i" } },
            { email: { $regex: safeSearch, $options: "i" } },
          ],
        });
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

export default app