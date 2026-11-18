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
app.post('/services', async (req, res) => {
  try {
    const serviceData = req.body;
    // ডিফল্টভাবে active true বা রিকোয়ারমেন্ট অনুযায়ী ফিল্ড সেট করা
    const newService = {
      ...serviceData,
      isActive: serviceData.isActive !== undefined ? serviceData.isActive : true,
      createdAt: new Date(),
    };

    const result = await servicesCollection.insertOne(newService);
    res.status(201).json({
      success: true,
      message: 'Service created successfully!',
      insertedId: result.insertedId,
      data: newService,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});




app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});