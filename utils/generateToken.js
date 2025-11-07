import jwt from "jsonwebtoken";
import ms from "ms";

/**
 * Generate short-lived access token
 */
export const generateAccessToken = (user) => {
  // ✅ Convert "15m" → milliseconds, then seconds
  const expiresInMs = ms(process.env.JWT_EXPIRE || "15m");
  const expiresInSeconds = Math.floor(expiresInMs / 1000);

  return jwt.sign(
    { id: user._id, role: user.role, tokenVersion: user.tokenVersion },
    process.env.JWT_SECRET,
    { expiresIn: expiresInSeconds } // ✅ use converted seconds
  );
};

/**
 * Generate long-lived refresh token
 */
export const generateRefreshToken = (user) => {
  const expiresInMs = ms(process.env.REFRESH_TOKEN_EXPIRE || "7d");
  const expiresInSeconds = Math.floor(expiresInMs / 1000);

  return jwt.sign(
    { id: user._id, role: user.role, tokenVersion: user.tokenVersion },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: expiresInSeconds } // ✅ consistent with access token logic
  );
};
