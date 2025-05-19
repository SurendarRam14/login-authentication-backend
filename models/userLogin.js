const mongoose = require("mongoose");

const userLoginSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
    },
    refreshToken: {
        type: String,
        required: true,
        unique: true,
    },
    isLoggedOut: {
        type: Boolean,
        required: true,
        default: false,
    },
    loginTime: {
        type: Date,
        required: true,
    },
    logoutTime: {
        type: Date,
        required: true,
    }

}, { collection: "userLoginDetails" });

module.exports = mongoose.model("UserLogin", userLoginSchema);