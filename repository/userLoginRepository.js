const UserLogin = require("../models/userLogin");

// Create a new user
const createUserLogin = async (userData) => {
    const user = new UserLogin(userData);
    return await user.save();
};

// Update user password
const updateLoginStatus = async (refreshToken, insertRecord) => {
    return await UserLogin.findOneAndUpdate(
        { refreshToken, isLoggedOut: false },
        insertRecord,
        { new: true } // Return the updated document
    );
};

module.exports = {
    createUserLogin,
    updateLoginStatus,
};