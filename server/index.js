const express = require("express");
const cors = require('cors');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const cookieparser = require('cookie-parser');
const fs = require('fs');
const mongoose = require('mongoose');
const User = require('./models/User');
const Post = require('./models/Post');
const dotenv = require('dotenv');

const app = express();
dotenv.config();

// Middleware to parse incoming JSON requests
app.use(bodyParser.json());
app.use(cors({ credentials: true, origin: process.env.FRONTEND_URL }));
app.use(express.json());
app.use(cookieparser());

const salt = bcrypt.genSaltSync(10);

// Middleware for handling file uploads (using multer)
const upload = multer({ dest: 'uploads/' });
app.use('/uploads', express.static(__dirname + '/uploads/'));

mongoose.connect(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true });

app.post('/register', async (req, res) => {
  const { firstname, email, password } = req.body;

  // Check if the password meets the minimum length requirement
  if (password.length < 8) {
      return res.status(400).json({ error: 'Password should be minimum of 8 characters' });
  }

  try {
      // Check if the firstname already exists in the database
      const existingUser = await User.findOne({ firstname });
      if (existingUser) {
          return res.status(400).json({ error: 'Firstname must be unique' });
      }

      // If firstname is unique, create the new user
      const userdoc = await User.create({
          firstname,
          email,
          password: bcrypt.hashSync(password, salt)
      });

      res.json(userdoc);
  } catch (e) {
      res.status(500).json({ error: 'Internal Server Error' });
  }
});



app.post('/login', async (req,res)  => {
    const {email,password} = req.body;
    try{
        const userdoc = await User.findOne({email:email});
        
      
        if(!userdoc){
            return res.status(400).json("User Not Found");
        }
        const ok = bcrypt.compareSync(password,userdoc.password);
        if(ok){
            jwt.sign({email, id : userdoc._id} , process.env.SECRET , {} , (err, token) => {
                    if(err) throw err;
                    res.cookie('token', token).json({
                        id:userdoc.id,
                        firstname:userdoc.firstname,
                        email,
                    });
                });
         }else{
         res.status(400).json("wrong credentials");
        }
    }catch(e){
        res.status(500).json(e.message);
    }
})


app.get('/profile', async (req, res) => {
    try {
        const { token } = req.cookies;

        if (!token) {
            return res.status(401).json("Token not provided");
        }

        const info = await jwt.verify(token, process.env.SECRET);

        if (!info || !info.id) {
            return res.status(401).json("Invalid token");
        }

        const user = await User.findById(info.id)

        if (!user) {
            return res.status(404).json("User not found");
        }

        res.json(
            
           user
        );

    } catch (err) {
              res.status(500).json("Internal Server Error");
    }
});


app.post('/logout' , (req,res) => {
    res.cookie('token','').json('ok');
   })



app.post('/upload', upload.single('image'), async (req, res) => {
  try {
    // const imagePath = req.file.path;

    const {originalname,path} = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length-1];
    const newpath = path+'.'+ext;
    fs.renameSync(path, newpath);

    const { token } = req.cookies;
        if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
        }

    jwt.verify(token, process.env.SECRET, {}, async (err, info) => {
      if (err) throw err;

      const { title, tags, description, content, link, sourcecode } = req.body;
      // Save imagePath and other data to MongoDB using Mongoose
      const newPost = new Post({
        title,
        tags,
        description,
        content,
        link,
        sourcecode,
        cover: newpath,
        upvotes: 0,
        author: info.id, // Assuming you have a field 'author' for the user who uploaded the post
      });
      // console.log(newPost);
      const savedPost = await newPost.save();

      // Respond with the saved post or any other desired response
      res.json({ success: true, post: savedPost });
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/post', async (req,res) => {
    const posts = await Post.find().populate('author',  ['firstname'])
    .sort({createdAt:-1}) 
    .limit(20);
     res.json(posts);
 })

 app.get('/post/:id' , async (req,res ) => {
    const {id} = req.params;
    const postdoc = await Post.findById(id).populate('author',  ['firstname']) 
    // console.log(postdoc);  
    res.json(postdoc);
})


app.put('/post/:id/upvote', async (req, res) => {
    const id = req.params.id;
    
  
    // Find the post by ID
    
  
   
      // Update the upvotes count
      const postdoc = await Post.findById(id);
      if (!(postdoc)) {
        return res.status(403).json({ error: 'Unauthorized user' });
    }
    // console.log(postdoc);
    await postdoc.updateOne({
       
       upvotes:postdoc.upvotes+1,
    });
      // Respond with the updated post
    res.json(postdoc);
    
      // Post not found
    
  });
  
  app.put('/post', upload.single('file'), async (req, res) => {
    try {

      const { token } = req.cookies;
      if (!token) {
        return res.status(401).json({ error: 'Token not provided' });
      }
  
      jwt.verify(token, process.env.SECRET, {}, async (err, info) => {
        if (err) {
          throw err;
        }
  
        // Post Authorization 
        const { id, title, tags, description, content, link, sourcecode} = req.body;
        const postdoc = await Post.findById(id);
        const isAuthor = JSON.stringify(postdoc.author) === JSON.stringify(info.id);
        if (!isAuthor) {
          return res.status(403).json({ error: 'Unauthorized user' });
        }
  
        // Update Post
        await postdoc.updateOne({
          title,
          tags,
          description,
          content,
          link,
          sourcecode,
          // cover: newpath,
          upvotes: postdoc.upvotes,
          author: info.id,
        });
  
        res.json(postdoc);
    // res.json();
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
  
    // Delete route
app.delete('/post/:postId', async (req, res) => {
      const { postId } = req.params;
      // console.log(postId);
      try {
        // Check if the provided ID is a valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(postId)) {
          return res.status(400).json({ error: 'Invalid post ID' });
        }

        // Find and delete the post
        const deletedPost = await Post.findByIdAndDelete(postId);

        // Check if the post was found and deleted
        if (!deletedPost) {
          return res.status(404).json({ error: 'Post not found' });
        }

        res.json({ message: 'Post deleted successfully' });
      } catch (error) {
      
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });    


    app.post('/yourprofile', async (req, res) => {
      try {
        const { token } = req.cookies;
        if (!token) {
            return res.status(401).json("Token not provided");
        }
        const info = await jwt.verify(token, process.env.SECRET);
        // console.log(info.id);
        try {
          // Assuming the Post model has an 'author' field
          const postdoc = await Post.find({ author: info.id });
          res.json({ posts: postdoc });
        } catch (error) {
      
          res.status(500).json({ error: 'Internal Server Error' });     
        }   
     
        // res.send(postdoc);
    } catch (err) {
        res.status(401).json("Invalid token");
    }
    });



// Route handler for saving comments

// Route handler for saving comments
app.post('/post/:id/comment', async (req, res) => {
  const { id } = req.params; // Extract post ID from URL
  const { commentedBy, text } = req.body; // Extract commentedBy and text from request body
  
  try {
      // Find the post by ID
      const post = await Post.findById(id);
      if (!post) {
          return res.status(404).json({ error: 'Post not found' });
      }
      
      // Create a new comment object with timestamps
      const newComment = {
          commentedBy,
          text,
          createdAt: new Date() // Set the createdAt field to the current date and time
      };
  
      // Add the new comment to the post's comments array
      post.comments.push(newComment);
      
      // Save the updated post
      await post.save();
      
      res.status(201).json({ message: 'Comment added successfully', post });
  } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
  }
  
});



// Route handler for getting all comments of a post
app.get('/post/:id/comments', async (req, res) => {
  const { id } = req.params; // Extract post ID from URL

  try {
    // Find the post by ID
    const post = await Post.findById(id);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    // Send all comments associated with the post
    res.status(200).json({ comments: post.comments });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});
    

app.listen(process.env.PORT || 4000);
