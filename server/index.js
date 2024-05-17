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

// Configure CORS
app.use(cors({
    credentials: true,
    origin: process.env.FRONTEND_URL
}));

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

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const userdoc = await User.findOne({ email: email });

        if (!userdoc) {
            return res.status(400).json("User Not Found");
        }
        const ok = bcrypt.compareSync(password, userdoc.password);
        if (ok) {
            jwt.sign({ email, id: userdoc._id }, process.env.SECRET, {}, (err, token) => {
                if (err) throw err;
                res.cookie('token', token).json({
                    id: userdoc.id,
                    firstname: userdoc.firstname,
                    email,
                });
            });
        } else {
            res.status(400).json("wrong credentials");
        }
    } catch (e) {
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

        res.json(user);

    } catch (err) {
        res.status(500).json("Internal Server Error");
    }
});

app.post('/logout', (req, res) => {
    res.cookie('token', '').json('ok');
})

app.post('/upload', upload.single('image'), async (req, res) => {
    try {
        const { originalname, path } = req.file;
        const parts = originalname.split('.');
        const ext = parts[parts.length - 1];
        const newpath = path + '.' + ext;
        fs.renameSync(path, newpath);

        const { token } = req.cookies;
        if (!token) {
            return res.status(401).json({ error: 'Token not provided' });
        }

        jwt.verify(token, process.env.SECRET, {}, async (err, info) => {
            if (err) throw err;

            const { title, tags, description, content, link, sourcecode } = req.body;
            const newPost = new Post({
                title,
                tags,
                description,
                content,
                link,
                sourcecode,
                cover: newpath,
                upvotes: 0,
                author: info.id,
            });
            const savedPost = await newPost.save();

            res.json({ success: true, post: savedPost });
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/post', async (req, res) => {
    const posts = await Post.find().populate('author', ['firstname'])
        .sort({ createdAt: -1 })
        .limit(20);
    res.json(posts);
})

app.get('/post/:id', async (req, res) => {
    const { id } = req.params;
    const postdoc = await Post.findById(id).populate('author', ['firstname'])
    res.json(postdoc);
})

app.put('/post/:id/upvote', async (req, res) => {
    const id = req.params.id;
    const postdoc = await Post.findById(id);
    if (!postdoc) {
        return res.status(403).json({ error: 'Unauthorized user' });
    }
    await postdoc.updateOne({
        upvotes: postdoc.upvotes + 1,
    });
    res.json(postdoc);
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

            const { id, title, tags, description, content, link, sourcecode } = req.body;
            const postdoc = await Post.findById(id);
            const isAuthor = JSON.stringify(postdoc.author) === JSON.stringify(info.id);
            if (!isAuthor) {
                return res.status(403).json({ error: 'Unauthorized user' });
            }

            await postdoc.updateOne({
                title,
                tags,
                description,
                content,
                link,
                sourcecode,
                upvotes: postdoc.upvotes,
                author: info.id,
            });

            res.json(postdoc);
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/post/:postId', async (req, res) => {
    const { postId } = req.params;
    try {
        if (!mongoose.Types.ObjectId.isValid(postId)) {
            return res.status(400).json({ error: 'Invalid post ID' });
        }

        const deletedPost = await Post.findByIdAndDelete(postId);
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
        const postdoc = await Post.find({ author: info.id });
        res.json({ posts: postdoc });
    } catch (err) {
        res.status(401).json("Invalid token");
    }
});

app.post('/post/:id/comment', async (req, res) => {
    const { id } = req.params;
    const { commentedBy, text } = req.body;

    try {
        const post = await Post.findById(id);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const newComment = {
            commentedBy,
            text,
            createdAt: new Date()
        };

        post.comments.push(newComment);
        await post.save();

        res.status(201).json({ message: 'Comment added successfully', post });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/post/:id/comments', async (req, res) => {
    const { id } = req.params;

    try {
        const post = await Post.findById(id);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        res.status(200).json(post.comments);
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(process.env.PORT || 4000);

