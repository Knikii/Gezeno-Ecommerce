const mongoose = require("mongoose");

const wishlistschema = new mongoose.Schema({
    userid: {
         type: mongoose.Schema.Types.ObjectId, ref: 'users',required:true
    },
    productid: {
          type: mongoose.Schema.Types.ObjectId, ref: 'Product',required:true
    }
});

module.exports = mongoose.model('wishlist',wishlistschema)