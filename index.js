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
    // JWT RELATED API
    app.post('/jwt',async (req,res)=>{
        const user = req.body;
        const token = jwt.sign(user,secret,{expiresIn: '2h'})
        res.send({token});
    })
    // MiddleWares : Verify Token
    const verifyToken = (req,res,next)=>{
      console.log('Inside Verify token : ',req.headers.authorization);
      if(!req.headers.authorization){
        return res.status(401).send({message:'Unauthorized Access!'})
      }
      const token = req.headers.authorization.split(' ')[1];
      // if(!token){
      //   return res.status(401).send({message:'Unauthorized Access!'})
      // }
      jwt.verify(token,secret,(error,decoded)=>{
        if(error){
          return res.status(401).send({message:'Unauthorized Access!'})
        }
        req.decoded = decoded;
        next();
      })
    }
    //MiddleWares: Verfy Admin after Verify Token
    const verifyAdmin = async (req,res,next)=>{
      const email = req.decoded.email;
      // console.log('Inside Admin Verify token : ',email);
      const query = { email };
      const user = await usersCollection.findOne(query);
      const isAdmin = user?.role === 'admin';
      if(!isAdmin){
        return res.status(403).send({message:'Forbidden Access!'})
      }
      next();
    }
    //MiddleWares: Verfy User after Verify Token
    const verifyUser = async (req,res,next)=>{
      const email = req.decoded.email;
      // console.log('Inside User Verify token : ',email);
      const query = { email };
      const user = await usersCollection.findOne(query);
      const isRole = user?.role === 'user';
      if(!isRole){
        return res.status(403).send({message:'Forbidden Access!'})
      }
      next();
    }
    //MiddleWares: Verfy Agent after Verify Token
    const verifyAgent = async (req,res,next)=>{
      const email = req.decoded.email;
      // console.log('Inside Agent Verify token : ',email);
      const query = { email };
      const user = await usersCollection.findOne(query);
      const isRole = user?.role === 'agent';
      if(!isRole){
        return res.status(403).send({message:'Forbidden Access!'})
      }
      next();
    }
    // User Routes
    // Get User Data that role is ADMIN or NOT
    app.get('/user/admin/:email',verifyToken,async (req,res)=>{
      let admin = false;
      const email = req.params.email;
      if(email !== req.decoded.email){
        return res.status(403).send({message:'Forbidden Access!'})
      }
      const filter = { email };
      const user = await usersCollection.findOne(filter);
      if(user){
        admin = user?.role === 'admin';
      }
      res.send({admin});
    })
    // Get User Data that role is User or Agent or notMentioned
    app.get('/user/role/:email',verifyToken,async (req,res)=>{
      let role = 'notMentioned';
      const email = req.params.email;
      if(email !== req.decoded.email){
        return res.status(403).send({message:'Forbidden Access!'})
      }
      const filter = { email };
      const user = await usersCollection.findOne(filter);
      if(user){
        role = user?.role;
      }
      res.send({role});
    })
    // Get User Data
      app.get('/user/:email',verifyToken, async (req,res)=>{
        const email = req.params.email;
        if(email !== req.decoded.email){
          return res.status(403).send({message:'Forbidden Access!'})
        }
        const query = {email}
        const result = await usersCollection.findOne(query);
        console.log('User Found!',result)
        res.send(result);
      })
      //Get All Users
      app.get('/users',verifyToken, async(req,res)=>{
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
      const {  lastSignInTime,email } = req.body;
      const filter = { email };
      const updatedUserInfo = {
        $set: {}
      };
      if (lastSignInTime) {
        updatedUserInfo.$set.lastSignInTime = lastSignInTime;
      }
      //
      const result = await usersCollection.updateOne(filter,updatedUserInfo);
      console.log('Updated Info of User',updatedUserInfo.$set);
      res.send(result);
      })
      // Update User Profile
      app.patch('/user',verifyToken,async (req,res)=>{
      const {  updatedAt,email, name,photo,bio } = req.body;
      if(email !== req.decoded.email){
        return res.status(403).send({message:'Forbidden Access!'})
      }
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
      if (updatedAt) {
        updatedUserInfo.$set.updatedAt = updatedAt;
      }
      if (bio) {
        updatedUserInfo.$set.bio = bio;
      }
      //
      const result = await usersCollection.updateOne(filter,updatedUserInfo);
      console.log('Updated Info of User',updatedUserInfo.$set);
      res.send(result);
      })
      // Update User Role For Social Login
      app.patch('/userRole',verifyToken,async (req,res)=>{
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
      // Change Role : Only Admin 
      app.patch('/users/role/:id', verifyToken, verifyAdmin, async (req,res)=>{
        const id = req.params.id;
        const { role } = req.body;
        const filter = {_id : new ObjectId(id)}
        const updatedUserInfo = {
          $set: {role}
        };
        const result = await usersCollection.updateOne(filter,updatedUserInfo);
        console.log(`Updated User to ${role}`);
        res.send(result);
      })
      // Delete User
      app.delete('/users/:id', verifyToken, verifyAdmin, async (req,res)=>{
        const id = req.params.id;
        const query = {_id : new ObjectId(id)}
        const result = await usersCollection.deleteOne(query);
        console.log('User deleted!')
        res.send(result);
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
    console.log(`PHRealState Server is Running on Port : ${port} `);
    // console.log(`PHRealState Server is Running on Port : ${port} and Secret : ${secret}`);
})