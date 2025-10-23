import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import connectDB from "./config/db.js";
import helmet from "helmet";
import xss from "xss-clean";

// Routes
import authRoutes from "./routes/authRoutes.js";

// Error Middleware
import { errorHandler } from "./middleware/errorHandler.js";

import { globalLimiter, speedLimiter } from "./middleware/rateLimiter.js";

dotenv.config();
connectDB();

const app = express();

app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(morgan("dev"));
app.use(cookieParser());
app.use(helmet());
app.use(xss());
app.use(globalLimiter);
app.use(speedLimiter);

// Routes
app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
  res.send("API is running...");
});

// Global Error Handler
app.use(errorHandler);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
