// server.js
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import xss from "xss-clean";
import connectDB from "./config/db.js";

// Routes
import authRoutes from "./routes/authRoutes.js";

// Error Middleware
import { errorHandler } from "./middleware/errorHandler.js";

// Rate Limiting Middleware
import { globalLimiter, speedLimiter } from "./middleware/rateLimiter.js";

dotenv.config();

// ✅ Connect to Database
connectDB();

const app = express();

// ✅ Trust Proxy (needed for Render, Nginx, etc.)
app.set("trust proxy", 1);

// ✅ Core Middleware (Security → Parsing → Logging)
app.use(helmet()); // Secure HTTP headers
app.use(xss()); // Prevent XSS attacks
app.use(express.json({ limit: "10kb" })); // Parse JSON safely
app.use(cookieParser()); // Parse cookies
app.use(morgan("dev")); // Logging

// ✅ Rate Limiting (protect APIs)
app.use(globalLimiter);
app.use(speedLimiter);

// ✅ CORS Setup (Allow cross-origin + cookies)
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ✅ Health Check Route
app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "✅ MCOM API is running securely...",
    environment: process.env.NODE_ENV || "development",
  });
});

// ✅ Main Routes
app.use("/api/auth", authRoutes);

// ✅ Global Error Handler
app.use(errorHandler);

// ✅ Graceful Server Startup
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(
    `🚀 Server running on port ${PORT} (${process.env.NODE_ENV || "development"})`
  )
);
