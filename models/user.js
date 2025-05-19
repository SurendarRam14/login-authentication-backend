const mongoose = require("mongoose");

const userAuthSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    username: {
        type: String,
        required: true,
    },
    isDeleted: {
        type: Boolean,
        required: true,
    },
    createdDate: {
        type: Date,
        required: true,
    },
    lastPasswordUpdatedDate: {
        type: Date,
        required: true,
    },
    lastModifiedDate: {
        type: Date,
        required: true,
    }

}, { collection: "userDetails" });

module.exports = mongoose.model("User", userAuthSchema);