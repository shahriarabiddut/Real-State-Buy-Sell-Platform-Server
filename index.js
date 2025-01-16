require('dotenv').config()
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
// Variables
const port = process.env.PORT || 3000;
const secret = process.env.JWTSECRET;
// App
const app = express();

// middleware
app.use(cors())
app.use(express.json())

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
    const usersCollection = client.db(dbName).collection("users");
    // User Routes
    // Get User Data
      app.get('/user/:email', async (req,res)=>{
        const email = req.params.email;
        const query = {email}
        const result = await usersCollection.findOne(query);
        console.log('User Found!')
        res.send(result);
      })
      //Get All Users
      app.get('/users', async(req,res)=>{
          const result = await usersCollection.find().toArray();
          console.log(`All Users Fetched!`);
          res.send(result);
      });
      // Add New User
      app.post('/users',async (req,res)=>{
        const user = req.body;
        let role = 'notMentioned';
        if(user.role){
          role = user.role === 'agent' ? 'agent' : 'user';
        }
        const userModified = {...user,role};
        const result = await usersCollection.insertOne(userModified);
        res.send(result);
      })
      // Update Login info Using Patch
      app.patch('/users',async (req,res)=>{
      const {  lastSignInTime,email, name,photo } = req.body;
      const filter = { email };
      const updatedUserInfo = {
        $set: {}
      };
      //if data provided then update
      if (name) {
        updatedUserInfo.$set.name = name;
      }
      if (photo) {
        updatedUserInfo.$set.photo = photo;
      }
      if (lastSignInTime) {
        updatedUserInfo.$set.lastSignInTime = lastSignInTime;
      }
      //
      const result = await usersCollection.updateOne(filter,updatedUserInfo);
      console.log('Updated Info of User',updatedUserInfo.$set);
      res.send(result);
      })
      // Update User ROle For Social Login
      app.patch('/userRole',async (req,res)=>{
      const { email, role,updatedAt } = req.body;
      // Allready have a role or not
      const query = {email}
      const existingUser = await usersCollection.findOne(query);
      if(existingUser.role != 'notMentioned'){
        return res.status(403).json({ error: 'Cannot change the role of this user.' });
      }else{
      const filter = { email };
      const updatedUserInfo = {
        $set: {}
      };
      //if data provided then update
      if (role) {
        updatedUserInfo.$set.role = role;
      }
      updatedUserInfo.$set.updatedAt = updatedAt;
      //
      const result = await usersCollection.updateOne(filter,updatedUserInfo);
      console.log('Updated Info of User',result);
      res.send(result);
        }
      // 
      
      })
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