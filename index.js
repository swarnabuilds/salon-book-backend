import express from 'express';
import cors from 'cors';
import 'dotenv/config'
import { MongoClient } from 'mongodb';
import { ObjectId } from "mongodb";


const app = express();
const port = process.env.PORT ||  5000;

app.use(
  cors({
    origin: ["http://localhost:3000", process.env.CLIENT_URL].filter(Boolean),
    credentials: true,
  })
);
app.use(express.json())


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



// services related api 
// Create a new service using  creator email
app.post("/services", async (req, res) => {
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

    const newService = {
      ...serviceData,
      serviceName,
      price: Number(serviceData.price) || 0,
      isActive:
        typeof serviceData.isActive === "boolean"
          ? serviceData.isActive
          : serviceData.status !== "inactive",
      createdBy: String(serviceData.createdBy).trim().toLowerCase(),
      createdAt: new Date(),
    };

    const result = await servicesCollection.insertOne(newService);
    return res.status(201).json({
      success: true,
      message: "Service created successfully.",
      data: {
        _id: result.insertedId,
        ...newService,
      },
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
    const { category, search, limit } = req.query;
    let query = { isActive: true };

    // Filter services by category if a category is provided
    // Skip category filtering when the category is "All"
    if (category && category !== 'All') {
      query.category = category;
    }

    // Search services by serviceName if a search value is provided
    if (search) {
      query.serviceName = {
        $regex: search,
        $options: 'i'
      };
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
    res.status(200).json({
      success: true,
      count: services.length,
      data: services,
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

    return res.status(200).json({
      success: true,
      data: service,
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
app.delete("/services/:id", async (req, res) => {
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
app.patch("/services/:id", async (req, res) => {
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
      cleanUpdate.price = Number(cleanUpdate.price) || 0;
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
      data: updatedService,
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
// Create a new appointment booking (without authMiddleware for now)

app.post("/appointments", async (req, res) => {
  try {
    const {
      serviceId,
      appointmentDate,
      timeSlot,
      message,
      customerId,
      customerName,
      customerEmail,
      customerRole,
    } = req.body;

    // Validate required fields
    if (!serviceId || !customerEmail || !appointmentDate || !timeSlot) {
      return res.status(400).json({
        success: false,
        message: "Required fields are missing.",
      });
    }

    // Allow only customers to book appointments
    const normalizedRole = String(customerRole || "customer").trim().toLowerCase();
    if (normalizedRole !== "customer") {
      return res.status(403).json({
        success: false,
        message: "Only customers can book appointments.",
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
      customerId: customerId || "",
      customerName: String(customerName || "").trim(),
      customerEmail: String(customerEmail).trim().toLowerCase(),
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


// Get appointments (filtered by customerEmail)
app.get("/appointments", async (req, res) => {
  try {
    const { email, status } = req.query;
    const query = {};

    if (email) {
      query.customerEmail = String(email).trim().toLowerCase();
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

        return {
          ...item,
          serviceImage,
          serviceCategory,
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
      const normalizedPayment = String(paymentStatus).trim().toLowerCase();
      if (!["paid", "unpaid"].includes(normalizedPayment)) {
        return res.status(400).json({
          success: false,
          message: "Invalid payment status.",
        });
      }

      await appointmentsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            paymentStatus: normalizedPayment,
            ...(stripeSessionId ? { stripeSessionId } : {}),
            paidAt: new Date(),
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
            amount: Number(amount ?? existing.servicePrice ?? 0),
            currency: String(currency || "USD").toUpperCase(),
            stripeSessionId: stripeSessionId || `session_${id}`,
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

    // Handle booking status update (confirmed, completed, cancelled)
    const nextStatus = String(status || "").trim().toLowerCase();
    const allowedStatuses = ["confirmed", "completed", "cancelled"];

    if (!allowedStatuses.includes(nextStatus)) {
      return res.status(400).json({
        success: false,
        message: "Unsupported update operation.",
      });
    }

    const currentStatus = String(existing.status || "pending").toLowerCase();

    if (nextStatus === "cancelled" && currentStatus !== "pending") {
      return res.status(400).json({
        success: false,
        message: `Cannot cancel an already ${currentStatus} appointment.`,
      });
    }

    if (nextStatus === "confirmed" && currentStatus === "cancelled") {
      return res.status(400).json({
        success: false,
        message: "Cannot confirm a cancelled appointment.",
      });
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
app.get("/transactions", async (req, res) => {
  try {
    const transactions = await transactionsCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    return res.status(200).json({
      success: true,
      data: transactions,
    });
  } catch (error) {
    console.error("GET /transactions error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to load transactions.",
    });
  }
});


app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});