import rateLimit from "express-rate-limit";
import slowDown from "express-slow-down";

// Global limiter (all routes)
export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests
  message: {
    success: false,
    message: "Too many requests from this IP. Please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Auth-specific limiter (tighter)
export const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // only 5 login/register attempts
  message: {
    success: false,
    message: "Too many login attempts. Try again later.",
  },
});

// Add slight delay for abusive clients
export const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 50, // allow 50 reqs at normal speed
  delayMs: 500, // add 0.5 s per extra request
});
