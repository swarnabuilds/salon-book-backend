import express from 'express';
import cors from 'cors';
import 'dotenv/config'
import { MongoClient } from 'mongodb';


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

// 1. Create a new service (POST API)
// Create a new salon service using  creator email
app.post("/services", async (req, res) => {
  try {
    const serviceData = req.body;

    // Ensure required fields and creator email are present
    if (!serviceData.name || !serviceData.category || !serviceData.createdBy) {
      return res.status(400).json({
        success: false,
        message: "Service name, category, and createdBy email are required.",
      });
    }

    const newService = {
      ...serviceData,
      price: Number(serviceData.price) || 0,
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


// 2. Get all services / active services (GET API)
// app.get('/services', async (req, res) => {
//   try {
//     const { category, search, limit } = req.query;
//     let query = { isActive: true }; // রিকোয়ারমেন্ট অনুযায়ী শুধু অ্যাক্টিভ সার্ভিসগুলো দেখাবে

//     if (category && category !== 'All') {
//       query.category = category;
//     }

//     if (search) {
//       query.name = { $regex: search, $options: 'i' };
//     }

//     let cursor = servicesCollection.find(query).sort({ createdAt: -1 });

//     if (limit) {
//       cursor = cursor.limit(Number(limit));
//     }

//     const services = await cursor.toArray();

//     res.status(200).json({
//       success: true,
//       count: services.length,
//       data: services,
//     });
//   } catch (error) {
//     res.status(500).json({ success: false, message: error.message });
//   }
// });



app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});