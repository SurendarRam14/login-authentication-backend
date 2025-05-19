const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const userRepository = require("../repository/authRepository");
const userLoginRepository = require("../repository/userLoginRepository");

// Helper function to generate tokens
const generateTokens = (userId) => {
    const accessToken = jwt.sign({ loginUserId: userId }, process.env.ACCESS_KEY, {
        expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN,
    });
    const refreshToken = jwt.sign({ loginUserId: userId }, process.env.REFRESH_KEY, {
        expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN,
    });
    return { accessToken, refreshToken };
};

// Login
const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log("LOGGING-IN", email, password)

        const user = await userRepository.findUserByEmail(email);
        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).send({ message: "Invalid credentials" });
        }

        const { accessToken, refreshToken } = generateTokens(user._id);

        req.session.userId = user._id;

        res.cookie("ATN", accessToken, {
            sameSite: "Lax",
            path: "/",
            maxAge: Number(process.env.ACCESS_TOKEN_EXPIRES_IN),
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
        });
        res.cookie("RTN", refreshToken, {
            sameSite: "Lax",
            path: "/",
            maxAge: Number(process.env.REFRESH_TOKEN_EXPIRES_IN),
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
        });

        const currentDate = new Date();
        await userLoginRepository.createUserLogin({
            userId: user._id,
            refreshToken,
            isLoggedOut: false,
            loginTime: currentDate,
            logoutTime: currentDate
        });

        res.status(200).send({ message: "Login successful", user });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).send({ message: "Internal Server Error" });
    }
};

// Register
const register = async (req, res) => {
    try {
        const { email, password, username } = req.body;

        const existingUser = await userRepository.findUserByEmail(email);
        if (existingUser) {
            return res.status(400).send({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const currentDate = new Date();
        const newUser = await userRepository.createUser({
            email,
            password: hashedPassword,
            username,
            isDeleted: false,
            createdDate: currentDate,
            lastPasswordUpdatedDate: currentDate,
            lastModifiedDate: currentDate
        });

        res.status(201).send({ message: "User registered successfully", user: newUser });
    } catch (error) {
        console.error("Register Error:", error);
        res.status(500).send({ message: "Internal Server Error" });
    }
};

// Update Password
const updatePassword = async (req, res) => {
    try {
        const { email, oldPassword, newPassword } = req.body;

        const user = await userRepository.findUserByEmail(email);
        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }

        const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
        if (!isPasswordValid) {
            return res.status(401).send({ message: "Invalid old password" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await userRepository.updateUserPassword(email, hashedPassword);

        res.status(200).send({ message: "Password updated successfully" });
    } catch (error) {
        console.error("Update Password Error:", error);
        res.status(500).send({ message: "Internal Server Error" });
    }
};

// Forgot Password
const forgotPassword = async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        const user = await userRepository.findUserByEmail(email);
        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await userRepository.updateUserPassword(email, hashedPassword);

        res.status(200).send({ message: "Password reset successfully" });
    } catch (error) {
        console.error("Forgot Password Error:", error);
        res.status(500).send({ message: "Internal Server Error" });
    }
};

// Logout
const logout = async (req, res) => {
    try {
        const refreshToken = req.cookies.RTN;
        if (!refreshToken) {
            return res.status(400).send({ message: "No active session found" });
        }

        // Find and update the user login record by refresh token
        const updatedRecord = await userLoginRepository.updateLoginStatus(refreshToken, {
            isLoggedOut: true,
            logoutTime: new Date(),
        });

        // Destroy session
        req.session.destroy((err) => {
            if (err) {
                console.error("Session destruction error:", err);
                return res.status(500).send({ message: "Logout failed" });
            }

            // Clear authentication cookies
            res.clearCookie("connect.sid");
            res.clearCookie("ATN");
            res.clearCookie("RTN");

            res.status(200).send({ message: "Logout successful" });
        });
    } catch (error) {
        console.error("Logout Error:", error);
        res.status(500).send({ message: "Internal Server Error" });
    }
};


module.exports = {
    login,
    register,
    updatePassword,
    forgotPassword,
    logout,
};