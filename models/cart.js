const mongoose = require("mongoose");

const cartschema = new mongoose.Schema({
    userid: {
         type: mongoose.Schema.Types.ObjectId, ref: 'users',required:true
    },
    productid: {
          type: mongoose.Schema.Types.ObjectId, ref: 'Product',required:true
    },
    qty: {
        type: Number,
        required:true,
    }
});

module.exports = mongoose.model('cart',cartschema)