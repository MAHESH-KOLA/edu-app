const mongoose = require('mongoose');
const {Schema, model}  = mongoose;

const UserSchema = new Schema({
    firstname : {type: String , required:true , minlength:4 , unique:true},
    email : {type: String , requried:true,unique:true},
    password : {type:String , required:true},
})

const UserModel = model('User',UserSchema);

module.exports = UserModel;