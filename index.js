const express = require("express");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const cors = require("cors");
const session = require("express-session");
const authentication = require("./routes/authRoutes");
const userLoginRepository = require("./repository/userLoginRepository");

dotenv.config();

const app = express();

// MongoDB Connection
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI + "/" + process.env.MONGO_DATABASE_NAME, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log("MongoDB connected successfully");
    } catch (error) {
        console.error("MongoDB connection error:", error);
        process.exit(1);
    }
};

connectDB();

// Session Configuration
app.use(
    session({
        secret: process.env.SESSION_SECRET || "your-secret-key",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: Number(process.env.SESSION_EXPIRES_IN),
            sameSite: "Lax",
        },
    })
);

// Middleware for handling proxies
const proxyMiddleware = () => {
    const verifyRefreshToken = (token) => {
        return new Promise((resolve, reject) => {
            jwt.verify(token, process.env.REFRESH_KEY, { algorithms: "HS256" }, (err, data) => {
                if (err) {
                    reject(new Error("Invalid Refresh Token"));
                } else {
                    resolve(data);
                }
            });
        });
    };

    const verifyAccessToken = (token) => {
        return new Promise((resolve, reject) => {
            jwt.verify(token, process.env.ACCESS_KEY, { algorithms: "HS256" }, (err, data) => {
                if (err) {
                    reject(new Error("Invalid Access Token"));
                } else {
                    resolve(data);
                }
            });
        });
    };

    const generateAccessToken = (userId) => {
        return jwt.sign({ loginUserId: userId }, process.env.ACCESS_KEY, {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN,
        });
    };

    const setAccessTokenCookie = (res, token) => {
        res.cookie("ATN", token, {
            sameSite: "Lax",
            path: "/",
            maxAge: Number(process.env.ACCESS_TOKEN_EXPIRES_IN),
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
        });
    };

    return async (req, res, next) => {
        try {
            // Bypass token validation for specific routes
            if (req.url.startsWith("/login") || req.url.startsWith("/register")) {
                return authentication(req, res, next);
            }

            // Check if cookies exist
            const { RTN, ATN } = req.cookies;
            console.log("COOKIES:::::::::::::::::::", RTN, ATN)
            if (!RTN) {
                return res.status(403).send({ message: "Refresh Token is required" });
            }

            let isApproved = false;

            // Verify Access Token if it exists
            if (ATN) {
                try {
                    await verifyAccessToken(ATN);
                    isApproved = true;
                } catch (error) {
                    console.log("Access Token expired or invalid, attempting to refresh...");
                }
            }

            // If Access Token is missing or invalid, verify Refresh Token
            if (!isApproved) {
                try {
                    const data = await verifyRefreshToken(RTN);
                    const newAccessToken = generateAccessToken(data?.loginUserId);
                    setAccessTokenCookie(res, newAccessToken);
                    isApproved = true;
                } catch (error) {
                    await userLoginRepository.updateLoginStatus(RTN, {
                        isLoggedOut: true,
                        logoutTime: new Date(),
                    });
                    return res.status(403).send({ message: "Invalid Refresh Token or Token expired" });
                }
            }

            if (req.url.startsWith("/logout") || req.url.startsWith("/updatePassword") || req.url.startsWith("/forgotPassword")) {
                return authentication(req, res, next); // Forward request to user routes
            }
        } catch (error) {
            console.error("Middleware Error:", error);
            res.status(500).send({ message: "Internal Server Error" });
        }
    };
};

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS Configuration
const corsConfig = {
    origin: process.env.CORS_ORIGIN || "*",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["X-Requested-With", "X-HTTP-Method-Override", "Content-Type", "Accept", "Authorization"],
};
app.use(cors(corsConfig));

// Custom proxy middleware
app.use(proxyMiddleware());

// Root route
app.get("/", (req, res) => {
    res.send("API is running...");
});

// Port Configuration & Server Start
const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Server is running on port: ${port}`);
});

module.exports = app;