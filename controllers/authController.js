import User from "../models/User.js";
import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import ms from "ms";
import {
  generateAccessToken,
  generateRefreshToken,
} from "../utils/generateToken.js";
import sendEmail from "../utils/sendEmail.js";
import RefreshToken from "../models/RefreshToken.js";

/**
 * Cookie Options (for HttpOnly Refresh Token)
 */
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production", // only true in production (HTTPS)
  sameSite: "strict",
  path: "/",
  maxAge: ms(process.env.REFRESH_TOKEN_EXPIRE || "7d"),
};

/**
 * @desc Register new user
 * @route POST /api/auth/register
 * @access Public
 */
export const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    throw new Error("All fields (name, email, password) are required");

  const existingUser = await User.findOne({ email });
  if (existingUser) throw new Error("User already exists");

  const user = await User.create({ name, email, password });

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  const expiresAt = new Date(Date.now() + cookieOptions.maxAge);

  await RefreshToken.create({
    token: refreshToken,
    user: user._id,
    expiresAt,
    ip: req.ip,
    userAgent: req.get("user-agent"),
  });

  // ✅ Store refresh token in HttpOnly cookie
  res.cookie("refreshToken", refreshToken, cookieOptions);

  res.status(201).json({
    success: true,
    message: "Registration successful",
    accessToken,
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  });
});

/**
 * @desc Login user
 * @route POST /api/auth/login
 * @access Public
 */
export const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) throw new Error("Email and password are required");

  const user = await User.findOne({ email }).select("+password");
  if (!user || !(await user.matchPassword(password)))
    throw new Error("Invalid email or password");

  // Delete old tokens for same user (rotation)
  await RefreshToken.deleteMany({ user: user._id });

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  const expiresAt = new Date(Date.now() + cookieOptions.maxAge);

  await RefreshToken.create({
    token: refreshToken,
    user: user._id,
    expiresAt,
    ip: req.ip,
    userAgent: req.get("user-agent"),
  });

  // ✅ Store refresh token securely in cookie
  res.cookie("refreshToken", refreshToken, cookieOptions);

  res.json({
    success: true,
    message: "Login successful",
    accessToken,
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  });
});

/**
 * @desc Refresh access token
 * @route POST /api/auth/refresh
 * @access Public
 */
export const refreshToken = asyncHandler(async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) throw new Error("No refresh token found");

  const stored = await RefreshToken.findOne({ token });
  if (!stored) throw new Error("Invalid refresh token");

  if (stored.expiresAt < new Date()) {
    await stored.deleteOne();
    throw new Error("Refresh token expired");
  }

  jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
    if (err) throw new Error("Invalid or tampered refresh token");

    const newAccessToken = generateAccessToken({
      _id: decoded.id,
      role: decoded.role,
      tokenVersion: decoded.tokenVersion,
    });

    res.json({ success: true, accessToken: newAccessToken });
  });
});

/**
 * @desc Logout user
 * @route POST /api/auth/logout
 * @access Public
 */
export const logoutUser = asyncHandler(async (req, res) => {
  const token = req.cookies.refreshToken;
  if (token) await RefreshToken.findOneAndDelete({ token });

  // ✅ Clear the cookie on logout
  res.clearCookie("refreshToken", cookieOptions);

  res.json({ success: true, message: "Logged out successfully" });
});

/**
 * @desc Forgot password
 * @route POST /api/auth/forgot-password
 * @access Public
 */
export const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  if (!email) throw new Error("Email is required");

  const user = await User.findOne({ email });
  if (!user) throw new Error("User not found");

  const resetToken = user.getResetPasswordToken();
  await user.save({ validateBeforeSave: false });

  const resetUrl = `${process.env.FRONTEND_URL}/auth/reset-password/${resetToken}`;
  const htmlMessage = `
    <h2>Password Reset Request</h2>
    <p>Hi ${user.name},</p>
    <p>Click below to reset your password. This link is valid for 10 minutes:</p>
    <a href="${resetUrl}" target="_blank">${resetUrl}</a>
  `;

  try {
    await sendEmail({
      email: user.email,
      subject: "Password Reset",
      message: htmlMessage,
    });
    res.json({
      success: true,
      message: "Password reset email sent successfully",
    });
  } catch (err) {
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save({ validateBeforeSave: false });
    throw new Error("Email could not be sent, please try again later");
  }
});

/**
 * @desc Reset password
 * @route PUT /api/auth/reset-password/:token
 * @access Public
 */
export const resetPassword = asyncHandler(async (req, res) => {
  const resetPasswordToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    resetPasswordToken,
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user) throw new Error("Invalid or expired reset token");

  user.password = req.body.password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;
  await user.save();

  res.json({ success: true, message: "Password reset successful" });
});

/**
 * @desc    Get current logged-in user
 * @route   GET /api/auth/me
 * @access  Private (requires token)
 */
export const getMe = asyncHandler(async (req, res) => {
  // req.user is set in protect middleware
  if (!req.user) {
    res.status(401);
    throw new Error("User not authorized");
  }

  res.status(200).json({
    success: true,
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      createdAt: req.user.createdAt,
      updatedAt: req.user.updatedAt,
    },
  });
});
