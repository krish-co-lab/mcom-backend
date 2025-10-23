// routes/authRoutes.js
import express from "express";
import { body } from "express-validator";
import { validateRequest } from "../middleware/validationRequest.js";
import {
  registerUser,
  loginUser,
  refreshToken,
  logoutUser,
} from "../controllers/authController.js";
import { authLimiter } from "../middleware/rateLimiter.js";

const router = express.Router();

// Register
router.post(
  "/register",
  [
    body("name").notEmpty().withMessage("Name is required"),
    body("email").isEmail().withMessage("Valid email required"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters"),
  ],
  authLimiter,
  validateRequest,
  registerUser
);

// Login
router.post(
  "/login",
  [
    body("email").isEmail().withMessage("Valid email required"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  authLimiter,
  validateRequest,
  loginUser
);

router.post("/refresh", refreshToken);
router.post("/logout", logoutUser);

export default router;
