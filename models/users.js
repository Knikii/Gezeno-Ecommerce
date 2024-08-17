const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const users = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "Please enter your name"],
        maxLength: [30, "Your name cannot exceed 30 characters"],
    },
    email: {
        type: String,
        required: [true, "Please enter your email"],
        unique: true,
        validate: [validator.isEmail, "Please enter valid email address"],
    },
    phone: {
        type: String,
        required: [false, "Please enter your phone number"],
        maxLength: [200, "Your phone number cannot exceed 200 characters"],
    },
    address: {
        type: String,
        required: [false, "Please enter your address"],
        maxLength: [200, "Your address cannot exceed 200 characters"],
    },
    password: {
        type: String,
        required: [true, "Please enter your password"],
        minlength: [6, "Your password must be longer than 6 characters"],
    },
    avatar: {
        public_id: {
            type: String,
            required: false,
        },
        url: {
            type: String,
            required: false,
        },
    },
    role: {
        type: String,
        default: "user",
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
});

module.exports = mongoose.model('users',users)