
// module.exports = Post;
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// Define the Comment schema with timestamps
const commentSchema = new Schema({
    commentedBy: { type: String }, // Assuming User model for commentedBy
    text: { type: String },
}, {
    timestamps: true // This will add createdAt and updatedAt fields to the comment schema
});

// Define the Project schema
const postSchema = new Schema({
    title: { type: String, required: true },
    tags: { type: String, required: true },
    cover: { type: String }, // Assuming this will store the path or URL of the image
    description: { type: String, required: true },
    content: { type: String, required: true },
    link: { type: String },
    upvotes: { type: Number, default: 0 },
    comments: [commentSchema], // Using the comment schema as a subdocument
    sourcecode: { type: String },
    author: { type: Schema.Types.ObjectId, ref: 'User' }   
}, {
    timestamps: true, // This will add createdAt and updatedAt fields to the post schema
});

// Create the Project model
const Post = mongoose.model('Project', postSchema);

module.exports = Post;
