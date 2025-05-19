const express = require("express");
const router = express.Router();
const controller = require("../controller/authController");

// Define routes
router.post("/login", controller.login);
router.post("/register", controller.register);
router.post("/updatePassword", controller.updatePassword);
router.post("/forgotPassword", controller.forgotPassword);
router.post("/logout", controller.logout);

module.exports = router;