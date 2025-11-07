// middleware/rateLimiter.js
import rateLimit from "express-rate-limit";
import slowDown from "express-slow-down";
import ms from "ms";

/**
 * 🧠 Global Rate Limiter — applied to all routes
 */
export const globalLimiter = rateLimit({
  windowMs: ms(process.env.RATE_LIMIT_GLOBAL_WINDOW || "15m"), // default 15 min
  limit: parseInt(process.env.RATE_LIMIT_GLOBAL_MAX || "100"), // v7+ uses 'limit'
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    console.warn(`⚠️ Global rate limit exceeded: ${req.ip}`);
    res.status(options.statusCode).json({
      success: false,
      message:
        "Too many requests from this IP. Please try again after some time.",
    });
  },
});

/**
 * 🔐 Auth Route Limiter — used for login/register
 */
export const authLimiter = rateLimit({
  windowMs: ms(process.env.RATE_LIMIT_AUTH_WINDOW || "10m"), // default 10 min
  limit: parseInt(process.env.RATE_LIMIT_AUTH_MAX || "5"), // only 5 attempts
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    console.warn(`🚫 Auth rate limit triggered for IP: ${req.ip}`);
    res.status(options.statusCode).json({
      success: false,
      message: "Too many login/register attempts. Please try again later.",
    });
  },
});

/**
 * 🐢 Speed Limiter — gradually slows abusive clients
 */
export const speedLimiter = slowDown({
  windowMs: ms(process.env.SPEED_LIMIT_WINDOW || "15m"),
  delayAfter: parseInt(process.env.SPEED_LIMIT_AFTER || "50"), // allow 50 requests
  delayMs: (hits) => Math.min(2000, hits * 100), // progressive delay (up to 2s)
});
