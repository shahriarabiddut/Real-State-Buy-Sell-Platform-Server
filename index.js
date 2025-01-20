require('dotenv').config()
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPESECRET);
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
    const wishlistCollection = client.db(dbName).collection("wishlist");
    const dealsCollection = client.db(dbName).collection("propertydeals");
    const paymentsCollection = client.db(dbName).collection("payments");
    const reviewsCollection = client.db(dbName).collection("reviews");
    // JWT RELATED API
    app.post('/jwt',async (req,res)=>{
        const user = req.body;
        const token = jwt.sign(user,secret,{expiresIn: '2h'})
        res.send({token});
    })
    // MiddleWares : Verify Token
    const verifyToken = (req,res,next)=>{
      // console.log('Inside Verify token ');
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
        const size = parseInt(req.query.size) || 12; 
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
      //Get All Agents
      app.get('/agents', async(req,res)=>{
        const page = parseInt(req.query.page) || 0; 
        const size = parseInt(req.query.size) || 12; 
        const result = await usersCollection.aggregate([
                                            {
                                              $match: { role: "agent" }, 
                                            },
                                            {
                                              $lookup: {
                                                from: "properties",
                                                localField: "email",
                                                foreignField: "agentEmail", 
                                                as: "properties",
                                              },
                                            },
                                            {
                                              $addFields: {
                                                propertyCount: { $size: "$properties" },
                                              },
                                            },
                                            {
                                              $sort: { propertyCount: -1 },
                                            },
                                            {
                                              $skip: page * size, 
                                            },
                                            {
                                              $limit: size, 
                                            },
                                            {
                                              $project: {
                                                name: 1,
                                                email: 1,
                                                role: 1,
                                                photo: 1,
                                                propertyCount: 1,
                                              },
                                            },
                                          ]).toArray();
        console.log(`All Agents Fetched!`);
        // For Pagination 
        const count = await usersCollection.countDocuments({role:'agent'});
        res.send({result,count});
      });
      // Get Popular City Properties
      // Property Routes
      // Get All Properies
      app.get('/property',async (req,res)=>{
        const email = req.query.email;
        const page = parseInt(req.query.page) || 0; 
        let size = parseInt(req.query.size) || 12; 
        const check = req.query.check ;
        const adv = req.query.adv ;
        let filter = {};
        // Search
        const location = req.query.location || '';
        const minPrice = req.query.minPrice || 0;
        const maxPrice = req.query.maxPrice || 0;
        const minsize = req.query.minsize || 0;
        if (location.trim() !== '') {
          filter.location = { $regex: location, $options: 'i' };
        }
        if (req.query.minPrice) {
          filter.minPrice = { $gte: parseInt(minPrice)};
        }
        if (req.query.maxPrice) {
          filter.maxPrice = { $lte: parseInt(maxPrice)};
        }
        if (req.query.minsize) {
          // console.log(minsize)
          filter.area = { $gte: parseInt(minsize)};
        }
        // 
        if (email !== '') {
          filter.agentEmail = email;
        }
        if (check !== '') {
          filter.status = 'verified';
        }
        if (adv !== '') {
          filter.advertisement = 1;
          size = 4;
        }
        let sortType = { _id: -1 };
        if (req.query.sort=='1') {
          sortType = { maxPrice: -1 };
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
                              _id: 1,title: 1,location: 1,image: 1,minPrice: 1,maxPrice: 1,area: 1,status: 1,agentEmail: 1,agentName: 1,advertisement:1,"agent.photo": 1 
                            }
                          }
                        ]).skip(page * size).limit(size).sort(sortType).toArray();
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
      // Verify Property Deal
      app.patch('/dealCheck', verifyToken, verifyAgent, async (req, res) => {
        const deal = req.body;
        const id = deal.id;
        const check = deal.check;
        const query = { _id: new ObjectId(id), status: { $ne: "rejected" } };
        const updatedProperty = {
          $set: {
            status: check,
          },
        };
        const result = await dealsCollection.updateOne(query, updatedProperty);
        console.log('Property Deal Checked: ', id);
        if (check === 'accepted' && result.modifiedCount > 0) {
          const acceptedDeal = await dealsCollection.findOne({ _id: new ObjectId(id) });
        if (acceptedDeal) {
          const rejectOtherDeals = await dealsCollection.updateMany(
            {
              propertyId: acceptedDeal.propertyId, 
              _id: { $ne: acceptedDeal._id }, 
            },
            { $set: { status: 'rejected' } } 
          );
          // If Advertised then remove advertise
          const upPropertyAdStatus = {
            $set: {
              advertisement: 0,
            },
          };
          const removeAd = await propertiesCollection.updateOne({ _id: new ObjectId(acceptedDeal.propertyId) },upPropertyAdStatus);
          console.log('If Advertised then remove advertise,Rejected Other Deals:', rejectOtherDeals.modifiedCount);
        }
      }
      res.send(result);
      });
      // Advertise - Remove Advertise Property
      app.patch('/propertyAdvertise',verifyToken,verifyAdmin,async (req,res)=>{
        const pro = req.body;
        const id = pro.id;
        const check = pro.check!='rejected'?1:0;
        const queryhowMany = {advertisement:1};
        const howMany = await propertiesCollection.countDocuments(queryhowMany);
        let result = []
        if(howMany<4 || check == 0){
          const query = {_id : new ObjectId(id),status: 'verified'}
          const updatedProperty = {
            $set: {
              advertisement:check,
            }
          };
          result = await propertiesCollection.updateOne(query,updatedProperty);
          console.log('Property Added For Advertisement : ',id);
        }
        res.send(result);
      })
      //Get Popular City Properties Count
      app.get('/popularcity', async(req,res)=>{
        try{
        const locations = ["dhaka", "rajshahi", "khulna"];
        const locationCounts = await Promise.all(
          locations.map(async (location) => {
            const filter = { location: { $regex: location, $options: 'i' } };
            const count = await propertiesCollection.countDocuments(filter);
            return { name: location, properties: count };
          })
          );
          res.send(locationCounts);
          } catch (error) {
            console.error("Error fetching popular city properties count:", error);
            res.status(500).json({ error: "Internal server error" });
          }
      });
      // WishList Routes
      // Get All Wishlist
      app.get('/wishlist',async (req,res)=>{
        const email = req.query.email ;
        const dashboard = req.query.dashboard ;
        const page = parseInt(req.query.page) || 0; 
        const size = parseInt(req.query.size) || 12; 
        let query ={}
        if(email!==''){
          query.email = email;
        }
        let result = [];
        const count = await wishlistCollection.countDocuments(query);
        if(dashboard){
          result = await wishlistCollection.aggregate([
                        {
                          $match: query, 
                        },
                        {
                          $addFields: { 
                            propertyId: { $toObjectId: "$propertyId" },
                          },
                        },
                        {
                          $lookup: {
                            from: "properties", 
                            localField: "propertyId", 
                            foreignField: "_id",
                            as: "propertyDetails", 
                          },
                        },
                        {
                          $unwind: "$propertyDetails", 
                        },
                         {
                          $lookup: {
                            from: "users", 
                            localField: "propertyDetails.agentEmail", 
                            foreignField: "email", 
                            as: "propertyDetails.agent", 
                          },
                        },
                        {
                          $unwind: {
                            path: "$propertyDetails.agent", 
                            preserveNullAndEmptyArrays: true, 
                          },
                        },{
                          $addFields: {
                            "propertyDetails.wishlistId": "$_id", 
                          },
                        },
                      ]).skip(page * size).limit(size).toArray();
        }else{
          result = await wishlistCollection.find(query).skip(page * size).limit(size).toArray();
          
        }
        res.send({result,count});
      })
      // Add To Wishlist
      app.post('/wishlist',verifyToken,verifyUser,async (req,res)=>{
        const wishlisted = req.body;
        const result = await wishlistCollection.insertOne(wishlisted);
        res.send(result);
      })
    // Delete Wishlist
      app.delete('/wishlist/:id',verifyToken,verifyUser,async (req,res)=>{
        const id = req.params.id;
        const query = {_id : new ObjectId(id)}
        const result = await wishlistCollection.deleteOne(query);
        console.log('Wishlist deleted!')
        res.send(result);
      })
    // Offer Routes
    // Get All Offers
      app.get('/deals',async (req,res)=>{
        const email = req.query.email ;
        const type = req.query.type ;
        const flag = req.query.flag ;
        
        const page = parseInt(req.query.page) || 0; 
        const size = parseInt(req.query.size) || 12; 
        let query ={}
        if(email!==''){
          if(type==='user'){query.buyerEmail = email;}else{query.agentEmail = email;}
        }
        if(flag!==''){
          query.flag = 1;
          query.status = 'bought';
        }
        const result = await dealsCollection.aggregate([
                        {
                          $match: query, 
                        },
                        {
                          $addFields: { 
                            propertyId: { $toObjectId: "$propertyId" },
                          },
                        },
                        {
                          $lookup: {
                            from: "properties", 
                            localField: "propertyId", 
                            foreignField: "_id",
                            as: "propertyDetails", 
                          },
                        },
                        {
                          $unwind: "$propertyDetails", 
                        },{
                          $addFields: {
                            "propertyDetails.dealId": "$_id", 
                            "propertyDetails.offerPrice": "$offerPrice", 
                            "propertyDetails.status": "$status", 
                            "propertyDetails.trId": "$transactionId", 
                          },
                        },
                        {
                          $project: {
                            "propertyDetails.deleteUrl": 0,
                            "propertyDetails.advertisement": 0,
                          },
                        },
                      ]).skip(page * size).limit(size).toArray();
        const count = await dealsCollection.countDocuments(query);
        res.send({result,count});
      })
      // Get Deal
      app.get('/deal/:id',async (req,res)=>{
        const id = req.params.id;
        const query = {_id : new ObjectId(id)}
        const result = await dealsCollection.findOne(query);
        console.log('Deal Found :',id);
        res.send(result);
      })
      // Get Deals Stats For Agent
      app.get('/dealStats/:email',verifyToken, verifyAgent,async (req,res)=>{
        const agentEmail = req.params.email;
        const query = {agentEmail : agentEmail,status: 'bought',flag:1}
        const result = await dealsCollection.aggregate([
                                            { $match: query }, 
                                            {
                                              $group: {
                                                _id: null, 
                                                totalDeals: { $sum: 1 }, 
                                                totalEarnings: { $sum: "$offerPrice" }, 
                                              },
                                            },
                                          ]).toArray();
        console.log('Deal Stats For Agent :',agentEmail);
        res.send(result);
      })

      // Add Offer 
      app.post('/deals',verifyToken,verifyUser,async (req,res)=>{
        const item = req.body;
        let status = 'pending';
        const dealFind = await dealsCollection.findOne({ propertyId: req.body.propertyId,status: { $nin: ['accepted', 'bought'] } });
        if(dealFind==null){
          status = 'rejected';
        }
        console.log(dealFind);
        const property = {...item,status:status,flag:0}
        const result = await dealsCollection.insertOne(property);
        console.log('New Property Offer Added!',status );
        res.send(result);
      })
      // Payment Routes
      // Payment Intent - Stripe
      app.post('/create-payment-intent',async(req,res)=>{
        const {price} = req.body;
        const amount = parseInt(price / 130);
        // BDT to USDT
        // Right: Should have divided by 1.3 ! 
        // Wrong: But It might cross the limit! so divided by 130 ! 
        const paymentIntent = await stripe.paymentIntents.create({
          amount : amount,
          currency: 'usd',
          payment_method_types: ['card']
        })
        res.send({
          clientSecret: paymentIntent.client_secret
        })
      })
      //  Save Payments
      app.post('/payments',verifyToken,async(req,res)=>{
        const payment = req.body;
        const transactionId = payment.transactionId; 
        const dealId = payment.dealId;
        const propertyId = payment.propertyId;
        const result = await paymentsCollection.insertOne(payment);
        // 
        const query = { _id: new ObjectId(dealId) };
        const updatedDeal = {
          $set: {
            flag: 1,transactionId: transactionId, status:'bought'
          },
        };
        const dealModify = await dealsCollection.updateOne(query, updatedDeal);
        // 
        const queryProperty = { _id: new ObjectId(propertyId) };
        const updatedProperty = {
          $set: {
            flag: 1,advertisement: 0, status:'sold'
          },
        };
        const propertyModify = await propertiesCollection.updateOne(queryProperty, updatedProperty);
        // 
        console.log('Payment Saved! ', payment)
        res.send({result,dealModify,propertyModify});
      })
      // Review Routes
      // Get All Reviews
      app.get('/review',async (req,res)=>{
        const email = req.query.email ;
        const dashboard = req.query.dashboard ;
        const id = req.query.id ;
        const page = parseInt(req.query.page) || 0; 
        const size = parseInt(req.query.size) || 12; 
        let query ={}
        if(email!=='' && id === ''){
          query.reviewerEmail = email;
        }
        if(id !== ''){
          query.propertyId = id;
        }
        let result = [];
        const count = await reviewsCollection.countDocuments(query);
        if(dashboard){
          result = await reviewsCollection.aggregate([
                        {
                          $match: query, 
                        },
                        {
                          $addFields: { 
                            propertyId: { $toObjectId: "$propertyId" },
                          },
                        },
                        {
                          $lookup: {
                            from: "properties", 
                            localField: "propertyId", 
                            foreignField: "_id",
                            as: "propertyDetails", 
                          },
                        },
                        {
                          $unwind: "$propertyDetails", 
                        },
                        {
                          $lookup: {
                            from: "users", 
                            localField: "reviewerEmail", 
                            foreignField: "email",
                            as: "reviewer", 
                          },
                        },
                        {
                          $unwind: "$reviewer", 
                        },
                        {
                          $project:{
                            _id:1,
                            propertyId:1,
                            "reviewer.photo" :1,
                            reviewerName: 1,
                            reviewerEmail:1,
                            description:1,
                            createdAt:1,
                            "propertyDetails.title" :1,
                            "propertyDetails.agentName" :1,
                          }
                          },
                          {
                            $sort: { _id: -1 }
                          },
                      ]).skip(page * size).limit(size).toArray();
        }
        else if(id){
          console.log('Single Review Called Mode!',query)
          // Get Specific Property Review
            result = await reviewsCollection.aggregate([
                        {
                          $match: query, 
                        },
                        {
                          $lookup: {
                            from: "users", 
                            localField: "reviewerEmail", 
                            foreignField: "email",
                            as: "reviewer", 
                          },
                        },
                        {
                          $unwind: "$reviewer", 
                        },
                      ]).skip(page * size).limit(size).sort({ _id: -1 }).toArray();
                      // console.log(result)
        }
        else{
          result = await reviewsCollection.find(query).skip(page * size).limit(size).sort({ _id: -1 }).toArray();
          
        }
        res.send({result,count});
      })
      // Add Review 
      app.post('/review',verifyToken,verifyUser,async (req,res)=>{
        const data = req.body;
        const review = {...data,flag:0}
        const result = await reviewsCollection.insertOne(review);
        console.log('New Review Added!');
        res.send(result);
      })
      // Delete Review - User
      app.delete('/review/:id',verifyToken,verifyUser,async (req,res)=>{
        const id = req.params.id;
        const query = {_id : new ObjectId(id)}
        const result = await reviewsCollection.deleteOne(query);
        console.log('Review deleted!')
        res.send(result);
      })
      // Delete Review - Admin
      app.delete('/reviewA/:id',verifyToken,verifyAdmin,async (req,res)=>{
        const id = req.params.id;
        const query = {_id : new ObjectId(id)}
        const result = await reviewsCollection.deleteOne(query);
        console.log('Review deleted!')
        res.send(result);
      })
      // Agent Stats - For Dashboard
      app.get('/agentStats/:email',verifyToken,verifyAgent,async (req,res)=>{
        const agentEmail = req.params.email;
        const query = {agentEmail : agentEmail,status: 'bought',flag:1}
        const result = await dealsCollection.aggregate([
                                            { $match: query }, 
                                            {
                                              $group: {
                                                _id: null, 
                                                totalDeals: { $sum: 1 }, 
                                                totalEarnings: { $sum: "$offerPrice" }, 
                                              },
                                            },
                                          ]).toArray();
          const totalProperty = await propertiesCollection.countDocuments({ agentEmail });
          const pendingOffers = await dealsCollection.countDocuments({ agentEmail,status: 'pending' });
          const totalDeals = result[0]?.totalDeals || 0;
          const totalEarnings = result[0]?.totalEarnings || 0;
          const stats = {totalDeals,totalEarnings,totalProperty,pendingOffers}
          console.log('Agent Stats :',agentEmail);
        res.send(stats);
      })
      // User Stats - For Dashboard
      app.get('/userStats/:email',verifyToken,verifyUser,async (req,res)=>{
        const email = req.params.email;
        const wishlistCount = await wishlistCollection.countDocuments({ email }); 
        const reviewsCount = await reviewsCollection.countDocuments({ reviewerEmail: email });
        const dealsStats = await dealsCollection.aggregate([
                                            { $match: { buyerEmail: email } }, 
                                            {
                                              $facet: {
                                                dealsOffered: [{ $count: "count" }], 
                                                totalSpent: [
                                                  { $match: { status: "bought" } }, 
                                                  { $group: { _id: null, totalSpent: { $sum: "$offerPrice" } } }, 
                                                ],
                                              },
                                            },
                                          ]).toArray();
        const dealsOffered = dealsStats[0]?.dealsOffered[0]?.count || 0;
        const totalSpent = dealsStats[0]?.totalSpent[0]?.totalSpent || 0;
        const stats = {wishlistCount,reviewsCount,dealsOffered,totalSpent}
        console.log('User Stats :',email);
        res.send(stats);
      })
      // Admin Stats - For Dashboard
      app.get('/adminStats/:email',verifyToken,verifyAdmin,async (req,res)=>{
        const email = req.params.email;
        const userCount = await wishlistCollection.countDocuments(); 
        const reviewsCount = await reviewsCollection.countDocuments();
        const propertiesCount = await propertiesCollection.countDocuments({status:'verified'});
        const paymentCount = await paymentsCollection.countDocuments();
        const stats = {userCount,reviewsCount,propertiesCount,paymentCount}
        console.log('User Stats :',email);
        res.send(stats);
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