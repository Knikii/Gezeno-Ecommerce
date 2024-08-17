const mongoose = require("mongoose")

const connectdb = async()=>{
    try{
    const connect = await mongoose.connect('mongodb://0.0.0.0:27017/gezeno')
    console.log("database is connected")
    }catch(err){
     console.log(err);
     process.exit(1);
    }
}
    
module.exports = connectdb;