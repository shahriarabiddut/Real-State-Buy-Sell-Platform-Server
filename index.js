require('dotenv').config()
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const app = express();
const jwt = require('jsonwebtoken');
const port = process.env.PORT || 5000;
const secret = process.env.JWTSECRET || 'secret';

app.use(express.json());

// Database
const dbName = process.env.DB_NAME;
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASSWORD;


// MongoDB Starts 
const uri = `mongodb+srv://${dbUser}:${dbPassword}@crudnodejs.33uff.mongodb.net/?retryWrites=true&w=majority&appName=crudNodeJs`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // DB Collections
    const userCollection = client.db(dbName).collection("users");
    // User Routes
      //Get All Users
      app.get('/users', async(req,res)=>{
          const result = await userCollection.find().toArray();
          console.log(`All Users Fetched!`);
          res.send(result);
      });
    // console.log("MongodB Pinged!");
    
  } finally {
    // Ensures that the client will close when you finish/error
    // console.log("Finally Executed!");
  }
}
run().catch(console.dir);
// MongoDB Ends

// Initial Setup
app.get('/', (req,res)=>{res.send(`PHRealState Server is Running!`)})
app.listen(port, ()=>{
    console.log(`PHRealState Server is Running on Port : ${port} and Secret : ${secret}`);
})