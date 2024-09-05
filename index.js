/**
rasib@gmail.com
 */


const express = require('express');
const app = express();
const cors = require('cors');
const port = 4000;
require('dotenv').config();
const jwt = require('jsonwebtoken')
//backend payment setup 1
const stripe = require('stripe')(process.env.SECRET_KEY)



// Middleware to parse JSON bodies
app.use(express.json());
app.use(cors());



const { MongoClient, ObjectId } = require('mongodb');


const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.drqortc.mongodb.net`;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB");

    const database = client.db('product4u');
    const productDatabase = database.collection('products');
    const userDatabase = database.collection('users');
    const reportDatabase = database.collection('reports')
    const reviewDatabase = database.collection('reviews')
    const paymentHistoruDatabase = database.collection('paymentHistory')
    const cuponsDatabase = database.collection('cupons')
    /**____________________________________________________________
     * -----------------JWT SECTION ---------------------------
     * ____________________________________________________________
     */
    //verify token
    const jwt = require('jsonwebtoken');

    const verifyToken = (req, res, next) => {
      // console.log("Inside verify token", req.headers.authorization);
    
      if (!req.headers.authorization) {
        return res.status(401).send({ message: "unauthorized access" });
      }
    

      const token = req.headers.authorization.split(' ')[1];
      // console.log("Token received:", token);
    
      jwt.verify(token, process.env.ACCESS_TOKEN_SECTET, (error, decoded) => {
        if (error) {
          return res.status(401).send({ message: "unauthorized access for error" });
        }
        req.decoded = decoded;
        // console.log(decoded)
        next();
      });
    };
    


    
  app.get("/halua",verifyToken,async(req,res)=>{
    const obj ={
      name:"rakib"
    }
    res.send(obj)
  })
  

   //after vefify token 
   const verifyAdmin = async (req, res, next) => {

    const email = req.decoded?.email;
    
    const query = { Email: email }
    const user = await userDatabase.findOne(query)
   console.log(user)
    const isAdmin = user?.user_Status === 'admin'

    if (!isAdmin) {
      return res.status(403).send({ message: 'forbidden access' })
    }
    next()
  }
  const verifyModerator = async (req, res, next) => {

    const email = req.decoded?.email;
    
    const query = { Email: email }
    const user = await userDatabase.findOne(query)
   console.log(user)
    const isAdmin = user?.user_Status === 'moderoator'

    if (!isAdmin) {
      return res.status(403).send({ message: 'forbidden access' })
    }
    next()
  }
  const verifyUser = async (req, res, next) => {

    const email = req.decoded?.email;
    
    const query = { Email: email }
    const user = await userDatabase.findOne(query)
   console.log(user)
    const isAdmin = user?.user_Status === 'user'

    if (!isAdmin) {
      return res.status(403).send({ message: 'forbidden access' })
    }
    next()
  }

    // Creating token
    app.post('/jwt', async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECTET, { expiresIn: '1h' })
      //  console.log(token)
      res.send({ token })
    })

    /**____________________________________________________________
     * -----------------USER SECTION ---------------------------
     * ____________________________________________________________
     */
    //create user D

    
    app.post('/user', async (req, res) => {
      const user = req.body;
      const query = { Email: user.email };

      try {
        const existingUser = await userDatabase.findOne(query);
        if (existingUser) {
          console.log('User already exists:', existingUser);
          return res.send({ message: "Already exists, please login" });
        }

        const result = await userDatabase.insertOne(user);
        console.log('User inserted:', result);
        res.send(result);
      } catch (error) {
        console.error('Error inserting user:', error);
        res.status(500).send({ message: 'An error occurred while inserting the user' });
      }
    });


    app.post('/auth/google', async (req, res) => {
      const { email, displayName, photoURL } = req.body;
  //  console.log(email, displayName, photoURL )
      try {
          const filter = { Email: email };
          const update = {
              $set: {
                Name: displayName,
                Email: email ,
                  Image: photoURL,
                  user_Status:"user",
                  Membership:false,
                  
              }
          };
          const options = { upsert: true, returnDocument: 'after' };
  
          // Update the user if exists or create a new user if it doesn't
          const result = await userDatabase.findOneAndUpdate(filter, update, options);
  
          // Respond with user data
          res.send(result);
      } catch (error) {
          res.status(500).send({ error: 'Internal Server Error' });
      }
  });
    /**____________________________________________________________
     * ------------------PRODUCT SECTION ---------------------------
     * ____________________________________________________________
     * 
     */
    //get all products D
    app.get('/products', async (req, res) => {
      try {
        const query = { status: "Accepted" }
        const result = await productDatabase.find(query).toArray();
        res.json(result);
      } catch (err) {
        console.error("Error fetching products:", err);
        res.status(500).json({ error: "Internal server error" });
      }
    });
    //add product D
    app.post('/products', async (req, res) => {
      try {
        const product = req.body;
        const email = req.query.email;
    
        if (!email) {
          return res.status(400).send({ status: 'error', message: "Email is required" });
        }
    
        const hasUser = await userDatabase.findOne({ Email: email });
    
        if (!hasUser) {
          return res.status(404).send({ status: 'error', message: "User not found" });
        }
    
        const hasProduct = await productDatabase.findOne({ OwnerEmail: email });
       
        // If user does not have membership and already has a product
        if (!hasUser.Membership && hasProduct) {
          return res.send({ status: 'error', message: "Sorry, please subscribe first!" });
        }
    
        // Setting additional fields for the product
        product.OwnerEmail = email;
        product.status = "pending";
    
        const result = await productDatabase.insertOne(product);
        res.send({ status: 'success', data: result });
    
      } catch (error) {
        console.error(error);
        res.status(500).send({ status: 'error', message: 'An error occurred while creating the product' });
      }
    });



    // get a single user products D
    app.get('/user/products', async (req, res) => {
      try {

        const email = req.query.email;

        if (!email) {
          return res.status(400).send({ message: "email is required" })
        }
        const query = { OwnerEmail: email }
        const result = await productDatabase.find(query).toArray();
        res.send(result)

      } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'An error occurred while creating the product' });
      }

    })
    //delete single product 
    app.delete('/user/products/:id', async (req, res) => {
      try {

        const id = req.params.id;
        const query = { _id: new ObjectId(id) }

        const result = await productDatabase.deleteOne(query);
        res.send(result)

      } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'An error occurred while creating the product' });
      }
    })
    //update single data D
    app.patch('/user/products/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const product = req.body;

        // Validate the product ID
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ error: 'Invalid product ID' });
        }

        const query = { _id: new ObjectId(id) };
        const update = { $set: product };

        // Assuming productDatabase is your MongoDB collection
        const result = await productDatabase.updateOne(query, update);

        // Check if the document was modified
        if (result.matchedCount === 0) {
          return res.status(404).send({ error: 'Product not found' });
        }

        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'An error occurred while updating the product' });
      }
    });
    //get single data by id

    app.get('/user/products/:id', async (req, res) => {
      try {
        const id = req.params.id;

        const query = { _id: new ObjectId(id) };
        const result = await productDatabase.findOne(query);
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'An error occurred while retrieving the product' });
      }
    });

    // increase upvote
    app.patch('/user/products/:id', async (req, res) => {
      try {
        const id = req.params.id;

        const query = { _id: new ObjectId(id) };
        const product = await productDatabase.findOne(query);
        if (!product) {
          return res.status(400).send({ message: 'Missing product field' });
        }
        const result = await productCollection.updateOne(
          { _id: new ObjectId(id) },
          { $inc: { upvote_count: 1 } }
        );
        res.send(result)
      } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'An error occurred while retrieving the product' });
      }
    })

    //add Report
    app.post('/product/report', async (req, res) => {
      try {
        const product = req.body;
        const email = req.query.email;
        const productId = product._id;
        delete product._id;

        if (!email) {
          return res.status(400).send({ message: "email is required" })
        }


        //seting as field;
        product.report = true;
        product.productId = productId;
        product.reported_user_Email = email;
        product.featured =false;
        const result = await reportDatabase.insertOne(product);
        res.send(result)

      } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'An error occurred while creating the product' });
      }

    })
    // get all
    app.get('/user/reportedProducts/',verifyToken,verifyModerator, async (req, res) => {
      try {

        const result = await reportDatabase.find().toArray();
        console.log(result)
        res.send(result)

      } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'An error occurred while creating the product' });
      }

    })

    // get a single product  reports(Problem)
    app.get('/user/reportedProducts/:id', async (req, res) => {
      try {

        const id = req.params.id;
        // res.json(id)
        const query = { productId: id }
        const query2 = { report: true }
        const result = await reportDatabase.find(query2).toArray();
        console.log(result)
        res.send(result)

      } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'An error occurred while creating the product' });
      }

    })
    //add review (Problem)
    app.post('/AddReviews', async (req, res) => {
      try {
        const review = req.body;
        const email = req.query.email;
        const productId = review.productId;
        // console.log(productId)
        // if(productId){
        //   return res.send({menssge:"No productId"})
        // }
        // console.log(productId)
        delete review.productId;


        const reviewObjectId = new ObjectId(productId)
        review.productId = reviewObjectId
        //  console.log(review)
        if (!email) {
          return res.status(401).send({ message: "email is required" })
        }
        const query1 = { reported_user_email: email ,productId:reviewObjectId}
        const alreadyReviewed = await reviewDatabase.findOne(query1)
        console.log(alreadyReviewed)
        if (alreadyReviewed) {
          return res.send({ message: "You already reviewed" })
        }
        //seting as field;
        review.reported_user_email = email;
        const result = await reviewDatabase.insertOne(review);
        // console.log(result)
        res.send(result)

      } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'An error occurred while creating the product' });
      }

    })
    //get product by id
    app.get('/reportedProducts/:productId', async (req, res) => {
      const productId = req.params.productId;
      //  console.log(productId)
      const result = await reviewDatabase.find({ productId: new ObjectId(productId) }).toArray()
      res.send(result)

    })


    //delete single report by id
    app.delete('/user/reviews/:id', async (req, res) => {
      try {

        const id = req.params.id;
        console.log(id)
        // res.send(id)
        const query = { _id: new ObjectId(id) }

        const result = await reviewDatabase.deleteOne(query);
        // console.log(result)
        res.send(result)

      } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'An error occurred while creating the product' });
      }
    })
    /**----------------------------------------------------
     * ---------------------Moderoator  ----------------
     * -------------------------------------------------
     */

    //get a single user by email
    app.get("/singleUser", async (req, res) => {
      const email = req.query.email;
      const query = { Email: email }
      const result = await userDatabase.findOne(query)
      res.send(result)
    })


// Get all products for moderation
app.get("/moderator/products", async (req, res) => {
  try {
      const products = await productDatabase.find().toArray();
      res.send(products);
  } catch (error) {
      console.error("Error fetching products:", error);
      res.status(500).send("Internal Server Error");
  }
});

// Mark product as featured
app.put("/product/featured/:id", async (req, res) => {
  const id = req.params.id;
  try {
      const result = await productDatabase.updateOne(
          { _id: new ObjectId(id) },
          { $set: { featured: true } }
      );
      res.send(result);
  } catch (error) {
      console.error("Error marking product as featured:", error);
      res.status(500).send("Internal Server Error");
  }
});

// Accept product
app.put("/product/accept/:id", async (req, res) => {
  const id = req.params.id;
  try {
      const result = await productDatabase.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: 'Accepted' } }
      );
      res.send(result);
  } catch (error) {
      console.error("Error accepting product:", error);
      res.status(500).send("Internal Server Error");
  }
});

// Reject product and remove featured status
app.put("/product/reject/:id", async (req, res) => {
  const id = req.params.id;
  try {
      const result = await productDatabase.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: 'Rejected', featured: false } }
      );
      res.send(result);
  } catch (error) {
      console.error("Error rejecting product:", error);
      res.status(500).send("Internal Server Error");
  }
});

// Get a single user by email
app.get("/singleUser", async (req, res) => {
  const email = req.query.email;
  const query = { Email: email };
  try {
      const result = await userDatabase.findOne(query);
      res.send(result);
  } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).send("Internal Server Error");
  }
});


    /**----------------------------------------------------
     * ---------------------Admin work ----------------
     * -------------------------------------------------
     */
/**
   // if(req.params.email!== req.decoded){
      //   return res.status(401).send({message: 'forbidden access'})
      // }
 */
    app.get("/users",verifyToken,verifyAdmin, async (req, res) => {
      console.log(req.decoded.email)
      // if(req.params.email!== req.decoded.email){
      //   return res.status(401).send({message: 'forbidden access'})
      // }
      const result = await userDatabase.find().toArray();
      res.send(result)
    })
    //makde moderator and

    app.put('/updateTomodetrator/:id', async (req, res) => {
      const userId = req.params.id;


      try {
        const result = await userDatabase.updateOne(
          { _id: new ObjectId(userId) },
          { $set: { user_Status: "moderoator" } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send('User not found');
        }

        res.send(result);
      } catch (error) {
        console.error('Error updating membership status:', error);
        res.status(500).send('An error occurred while updating membership status');
      }
    });
    app.put('/updateAdmin/:id', async (req, res) => {
      const userId = req.params.id;

      try {
        const result = await userDatabase.updateOne(
          { _id: new ObjectId(userId) },
          { $set: { user_Status: "admin" } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send(result);
        }

        res.send(result);
      } catch (error) {
        console.error('Error updating membership status:', error);
        res.status(500).send('An error occurred while updating membership status');
      }
    });
    app.put('/updateuser/:id', async (req, res) => {
      const userId = req.params.id;


      try {
        const result = await userDatabase.updateOne(
          { _id: new ObjectId(userId) },
          { $set: { user_Status: "user" } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send(result);
        }

        res.send(result);
      } catch (error) {
        console.error('Error updating membership status:', error);
        res.status(500).send('An error occurred while updating membership status');
      }
    });

// Get all users
app.get("/users", async (req, res) => {
  try {
      const users = await userDatabase.find().toArray();
      res.send(users);
  } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).send("Internal Server Error");
  }
});

// Update user to Moderator
app.put("/updateTomodetrator/:id", async (req, res) => {
  const id = req.params.id;
  try {
      const result = await userDatabase.updateOne(
          { _id: new ObjectId(id) },
          { $set: { user_Status: 'moderoator' } }
      );
      res.send(result);
  } catch (error) {
      console.error("Error updating to moderator:", error);
      res.status(500).send("Internal Server Error");
  }
});

// Update user to Admin
app.put("/updateAdmin/:id", async (req, res) => {
  const id = req.params.id;
  try {
      const result = await userDatabase.updateOne(
          { _id: new ObjectId(id) },
          { $set: { user_Status: 'admin' } }
      );
      res.send(result);
  } catch (error) {
      console.error("Error updating to admin:", error);
      res.status(500).send("Internal Server Error");
  }
});

// Update user to User
app.put("/updateUser/:id", async (req, res) => {
  const id = req.params.id;
  try {
      const result = await userDatabase.updateOne(
          { _id: new ObjectId(id) },
          { $set: { user_Status: 'user' } }
      );
      res.send(result);
  } catch (error) {
      console.error("Error updating to user:", error);
      res.status(500).send("Internal Server Error");
  }
});



    // Route to create a coupon (Admin)
    app.post('/coupons',verifyToken,verifyAdmin, async (req, res) => {
      const data = req.body;
      const email = req.query.email;
      data.email = email;

      const result = await cuponsDatabase.insertOne(data)
      res.send(result)
    });

    // Route to get all coupons (User)

    app.get('/coupons', async (req, res) => {
      try {
        // Fetch all coupons
        const result = await cuponsDatabase.find({}).toArray();

        // Check the length of the result
        if (result.length > 1) {
          // Sort the result in reverse order if length is more than 1
          const sortedResult = result.sort((a, b) => {
            if (a._id > b._id) return -1;
            if (a._id < b._id) return 1;
            return 0;
          });
          res.send(sortedResult);
        } else {
          res.send(result);
        }
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch coupons', error });
      }
    });



    // Route to apply a coupon (User)
    app.post('/apply-coupon', (req, res) => {
      const { couponCode } = req.body;
      db.collection('coupons').findOne({ code: couponCode }, (err, coupon) => {
        if (err) return res.status(500).send(err);
        if (!coupon) return res.status(404).send({ message: 'Coupon not found' });
        res.status(200).send({ message: 'Coupon applied', discount: coupon.discount });
      });
    });

    /**____________________________________________________________
       * ------------------Moderoator work  ---------------------------
       * ____________________________________________________________
       * 
       */

    //get all the reports
    app.get('/allReports',verifyToken,verifyModerator, async (req, res) => {
      try {
        const resullt = await reportDatabase.find().toArray()
        res.send(resullt)

      } catch (error) {
        console.log(error)
      }
    })
    //get product based on pending
    app.get('/moderoator/products', async (req, res) => {
      try {
        const query = {}
        const result = await productDatabase.find(query).toArray();
        res.json(result);
      } catch (err) {
        console.error("Error fetching products:", err);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    //delete report
    app.delete('/allUserReports/:id', async (req, res) => {
      try {

        const id = req.params.id;
        const query = { _id: new ObjectId(id) }

        const result = await reportDatabase.deleteOne(query);
        res.send(result)

      } catch (error) {
        console.error(error);
        res.status(500).send({ error: 'An error occurred while creating the product' });
      }
    })
    //feature (probel)
    app.put('/product/featured/:id', async (req, res) => {
      const productId = req.params.id;
      // console.log(productId)
      try {
        const query = { _id: new ObjectId(productId) };
        const update = { $set: { featured: true } };
        const result = await productDatabase.updateOne(query, update);
        //  console.log(result)
        if (result.modifiedCount === 1) {
          res.status(200).send({ message: 'Product marked as featured' });
        } else {
          res.status(404).send({ message: 'Product not found' });
        }
      } catch (error) {
        console.error('Error updating product:', error);
        res.status(500).send({ message: 'An error occurred while updating the product' });
      }
    });
    //accept  
    app.put('/product/accept/:id', async (req, res) => {
      const productId = req.params.id;

      try {
        // console.log(productId)
        const query = { _id: new ObjectId(productId) };
        const data = await productDatabase.find(query).toArray()
        // console.log(data)
        const update = { $set: { status: "Accepted" } };
        const result = await productDatabase.updateOne(query, update);

        if (result.modifiedCount === 1) {
          res.status(200).send({ message: 'Done' });
        } else {
          res.status(404).send({ message: 'Sorry' });
        }
      } catch (error) {
        console.error('Error updating product:', error);
        res.status(500).send({ message: 'An error occurred while updating the product' });
      }
    });
    //reject  
    app.put('/product/reject/:id', async (req, res) => {
      const productId = req.params.id;

      try {

        const query = { _id: new ObjectId(productId) };
        const update = { $set: { status: "Rejected" } };
        const result = await productDatabase.updateOne(query, update);
        if (result.modifiedCount === 1) {
          res.status(200).send({ message: 'Done' });
        } else {
          res.status(404).send({ message: 'Sorry' });
        }
      } catch (error) {
        console.error('Error updating product:', error);
        res.status(500).send({ message: 'An error occurred while updating the product' });
      }
    });

    /**____________________________________________________________
       * ------------------details Section  ---------------------------
       * ____________________________________________________________
       * 
       */
    //get all the repoet
    app.get("/reviews", async (req, res) => {
      const result = await reviewDatabase.find().toArray();
      res.send(result)
    })
    app.get("/reviews/:productId", async (req, res) => {
      const productId = req.params.productId;
      const result = await reviewDatabase.find({productId: new ObjectId(productId)}).toArray();
      res.send(result)
    })



    /**____________________________________________________________
       * ------------------Hoome Section  ---------------------------
       * ____________________________________________________________
       * 
       */

    //Tranding product
    app.get('/products/trending', async (req, res) => {
      try {

        const trendingProducts = await productDatabase.find()
          .sort({ upvote_count: -1 })
          .limit(8)
          .toArray()
        res.send(trendingProducts);
      } catch (error) {
        console.error('Error fetching trending products:', error);
        res.status(500).send({ message: 'An error occurred while fetching trending products' });
      }
    })
    app.get('/products/topFeatured', async (req, res) => {
      try {

        const trendingProducts = await productDatabase.find({ featured: true,status:"Accepted" })
          .toArray()
        res.send(trendingProducts);
      } catch (error) {
        console.error('Error fetching trending products:', error);
        res.status(500).send({ message: 'An error occurred while fetching trending products' });
      }
    })


    /**____________________________________________________________
   * ------------------payment Section  ---------------------------
   * ____________________________________________________________
   * 
*/



    //paymnet histry
    app.post('/payments',verifyToken, async (req, res) => {
      const paymemt = req.body;

      const { email, transactionId, date } = paymemt;
      // if (email !== req.decoded?.email) {
      //   return res.status(403).send({ message: "forbiden acess" })
      // }
      console.log(email, transactionId, date)
      const filter = { Email: email }; // Specify your filter criteria here
      const updateDoc = {
        $set: {
          transactionId: transactionId,
          date: date,
          Membership: true,
        },
      };

      const result = await userDatabase.updateOne(filter, updateDoc);
      // const result = await paymentHistoruDatabase.insertOne(paymemt);
      // if(req.params.email!== req.decoded){
      //   return res.status(401).send({message: 'forbidden access'})
      // }


      res.send(result)
    })

    app.post("/create-payment-intent", async (req, res) => {
      const { price } = req.body;

      // Validate the price
      if (price == null || isNaN(price) || price <= 0) {
        return res.status(400).send({ error: 'Invalid price provided' });
      }


      // Convert price to cents
      const amount = Math.round(price * 100); // Convert to cents

      // Custom minimum amount validation (Stripe minimum is typically $0.50 or 50 cents for USD)
      const minAmount = 1; // Minimum amount in cents (e.g., 50 cents)
      if (amount < minAmount) {
        return res.status(400).send({ error: 'Amount must be at least $0.50' });
      }

      try {
        // Create a PaymentIntent with the order amount and currency
        const paymentIntent = await stripe.paymentIntents.create({
          amount: amount,
          currency: "usd",
          payment_method_types: ['card']
        });

        res.send({
          clientSecret: paymentIntent.client_secret,
        });
      } catch (error) {
        console.error('Error creating payment intent:', error);
        res.status(500).send({ error: 'Failed to create payment intent' });
      }
    });




  } catch (err) {
    console.error("Error connecting to MongoDB:", err);
  }


}

run().catch(console.error);

// Route to get a welcome message
app.get('/', (req, res) => {
  res.send('Welcome to my basic Express server!');
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
