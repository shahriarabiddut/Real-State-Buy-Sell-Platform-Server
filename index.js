require('dotenv').config()
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
// Variables
const port = process.env.PORT || 3000;
const secret = process.env.JWTSECRET;
// Firebase SDK Set
const admin = require("firebase-admin");
const serviceAccount = require("./servicekey/phrealstate-firebase-adminsdk-xa9rb-a532980ce6.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

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
    const propertiesCollection = client.db(dbName).collection("properties");
    // JWT RELATED API
    app.post('/jwt',async (req,res)=>{
        const user = req.body;
        const token = jwt.sign(user,secret,{expiresIn: '2h'})
        res.send({token});
    })
    // MiddleWares : Verify Token
    const verifyToken = (req,res,next)=>{
      console.log('Inside Verify token ');
      // console.log('Inside Verify token : ',req.headers.authorization);
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
      app.get('/users', verifyToken,verifyAdmin, async(req,res)=>{
        const page = parseInt(req.query.page) || 0; 
        const size = parseInt(req.query.size) || 8; 
        const result = await usersCollection.find().skip(page * size).limit(size).sort({ _id: -1 }).toArray();
        console.log(`All Users Fetched!`);
        // For Pagination 
        const count = await usersCollection.countDocuments();
        res.send({result,count});
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
        if(role==='fraud'){
            const agent = await usersCollection.findOne(filter);
            const deleteProperties = await propertiesCollection.deleteMany({ agentEmail: agent.email });
            console.log(deleteProperties);
        }
        res.send(result);
      })
      // Delete User
      app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
        const id = req.params.id; 
        const email = req.query.email; 
        console.log(id, email);
        if (!email) {
          return res.status(400).json({ error: 'Email is required.' });
        }

        const query = { _id: new ObjectId(id) };
        try {
          const userRecord = await admin.auth().getUserByEmail(email); // Get user by email
          const uid = userRecord.uid; // Extract UID
          await admin.auth().deleteUser(uid); // Delete user from Firebase Authentication
          const message = `User with email ${email} deleted successfully.`;
          const result = await usersCollection.deleteOne(query);
          console.log('User deleted!', message);
          res.send(result);
        } catch (error) {
          console.error('Error deleting user:', error.message);
          res.status(500).json({ error: 'Error deleting user.' });
        }
      });

      // Property Routes
      // Get All Properies
      app.get('/property',async (req,res)=>{
        const email = req.query.email;
        const page = parseInt(req.query.page) || 0; 
        const size = parseInt(req.query.size) || 12; 
        const check = req.query.check ;
        const search = req.query.search || '';
        let filter = {};
        if (search.trim() !== '') {
          filter.location = { $regex: search, $options: 'i' };
        }
        if (email !== '') {
          filter.agentEmail = email;
        }
        if (check !== '') {
          filter.status = 'verified';
        }
        const result = await propertiesCollection.aggregate([
                          {
                            $match: filter 
                          },
                          {
                            $lookup: {
                              from: "users",localField: "agentEmail",foreignField: "email",as: "agent" 
                            }
                          }, {$unwind:'$agent'},
                          {
                            $project: {
                              _id: 1,title: 1,location: 1,image: 1,minPrice: 1,maxPrice: 1,area: 1,status: 1,agentEmail: 1,agentName: 1,
                              "agent.photo": 1 
                            }
                          }
                        ]).skip(page * size).limit(size).sort({ _id: -1 }).toArray();
        // For Pagination 
        const count = await propertiesCollection.countDocuments(filter);
        res.send({result,count});
      })
      app.get('/properties', async (req,res)=>{
          const result = await propertiesCollection.find().toArray();
          res.send(result);
      })
      
      // Get Property
      app.get('/property/:id',async (req,res)=>{
        const id = req.params.id;
        const query = {_id : new ObjectId(id)}
        const result = await propertiesCollection.findOne(query);
        console.log('Property Found :',id);
        res.send(result);
      })
      // Get Property For Edit
      app.get('/propertyEdit/:id',async (req,res)=>{
        const id = req.params.id;
        const query = {_id : new ObjectId(id),status: { $ne: "rejected" }}
        const result = await propertiesCollection.findOne(query);
        if (!result) {
          console.log('Property not found or Rejected');
          return res.status(404).send({ message: "Property not found or rejected." });
        }
        console.log('Property Found :',id);
        res.send(result);
      })
      // Add Property 
      app.post('/property',verifyToken,verifyAgent,async (req,res)=>{
        const item = req.body;
        const property = {...item,status:'pending',flag:0,advertisement:0}
        const result = await propertiesCollection.insertOne(property);
        console.log('New Property Added!');
        res.send(result);
      })
      // Update Propety
      app.patch('/property/:id', verifyToken, verifyAgent, async (req,res)=>{
        const id = req.params.id;
        // Check Owner
        const checkQuery = {_id : new ObjectId(id)}
        const checkOwner = await propertiesCollection.findOne(checkQuery);
        if(checkOwner.agentEmail !== req.decoded.email){
          return res.status(403).send({message:'Forbidden Access!'})
        }
        // 
        const filter = {_id : new ObjectId(id)}
        const updatedProperty = {
          $set: {
            title:property.title,
            location:property.location,
            image:property.image,
            minPrice:property.minPrice,
            maxPrice:property.maxPrice,
            area:property.area,
          }
        };
        const result = await propertiesCollection.updateOne(filter,updatedProperty);
        console.log(`Updated Property ${id}`);
        res.send(result);
      })
      // Verify Property
      app.patch('/propertyCheck',verifyToken,verifyAdmin,async (req,res)=>{
        const pro = req.body;
        const id = pro.id;
        const check = pro.check;
        const query = {_id : new ObjectId(id),status: { $ne: "rejected" }}
        const updatedProperty = {
          $set: {
            status:check,
          }
        };
        const result = await propertiesCollection.updateOne(query,updatedProperty);
        console.log('Property Checked : ',id);
        res.send(result);
      })
      // Delete Property
      app.delete('/property/:id',verifyToken,verifyAgent,async (req,res)=>{
        const id = req.params.id;
        const query = {_id : new ObjectId(id)}
        const result = await propertiesCollection.deleteOne(query);
        console.log('Property deleted!')
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