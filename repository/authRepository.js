const User = require("../models/user");

// Find user by email
const findUserByEmail = async (email) => {
    return await User.findOne({ email, isDeleted: false });
};

// Create a new user
const createUser = async (userData) => {
    const user = new User(userData);
    return await user.save();
};

// Update user password
const updateUserPassword = async (email, newPassword) => {
    return await User.findOneAndUpdate(
        { email, isDeleted: false },
        { password: newPassword, lastPasswordUpdatedDate: new Date() },
        { new: true } // Return the updated document
    );
};

module.exports = {
    findUserByEmail,
    createUser,
    updateUserPassword,
};