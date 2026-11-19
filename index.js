import express from 'express';
import cors from 'cors';
import 'dotenv/config'
import { MongoClient } from 'mongodb';
import { ObjectId } from "mongodb";



const app = express();
const port = process.env.PORT ||  5000;

app.use(cors())
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




app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});