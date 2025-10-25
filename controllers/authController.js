import User from "../models/User.js";
import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken"; // ✅ added import
import {
  generateAccessToken,
  generateRefreshToken,
} from "../utils/generateToken.js";
import sendEmail from "../utils/sendEmail.js";
import crypto from "crypto";
import RefreshToken from "../models/RefreshToken.js";
import ms from "ms"; // ✅ to calculate expiry duration

// @desc Register new user
// @route POST /api/auth/register
// @access Public
export const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  const userExists = await User.findOne({ email });
  if (userExists) throw new Error("User already exists");

  const user = await User.create({ name, email, password });

  // Generate tokens
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  // ✅ Add expiry date for refresh token
  const expiresAt = new Date(
    Date.now() + ms(process.env.REFRESH_TOKEN_EXPIRE || "7d")
  );

  await RefreshToken.create({
    token: refreshToken,
    user: user._id,
    expiresAt,
    ip: req.ip,
    userAgent: req.get("user-agent"),
  });

  res.status(201).json({
    success: true,
    accessToken,
    refreshToken,
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
  });
});

// @desc Login user
// @route POST /api/auth/login
// @access Public
export const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email }).select("+password");
  if (!user) throw new Error("Invalid credentials");

  const isMatch = await user.matchPassword(password);
  if (!isMatch) throw new Error("Invalid credentials");

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  const expiresAt = new Date(
    Date.now() + ms(process.env.REFRESH_TOKEN_EXPIRE || "7d")
  );

  // ✅ Clear old tokens for the same user (optional security improvement)
  await RefreshToken.deleteMany({ user: user._id });

  await RefreshToken.create({
    token: refreshToken,
    user: user._id,
    expiresAt,
    ip: req.ip,
    userAgent: req.get("user-agent"),
  });

  res.json({
    success: true,
    accessToken,
    refreshToken,
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
  });
});

// @desc Refresh Access Token
// @route POST /api/auth/refresh
// @access Public
export const refreshToken = asyncHandler(async (req, res) => {
  const { token } = req.body;
  if (!token) throw new Error("No refresh token provided");

  const storedToken = await RefreshToken.findOne({ token });
  if (!storedToken) throw new Error("Invalid refresh token");

  // ✅ Check expiration
  if (storedToken.expiresAt < new Date()) {
    await storedToken.deleteOne();
    throw new Error("Refresh token expired");
  }

  jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
    if (err) throw new Error("Invalid refresh token");

    const accessToken = generateAccessToken({
      _id: decoded.id,
      role: decoded.role,
    });
    res.json({ success: true, accessToken });
  });
});

// @desc Logout
// @route POST /api/auth/logout
// @access Public
export const logoutUser = asyncHandler(async (req, res) => {
  const { token } = req.body;
  await RefreshToken.findOneAndDelete({ token });
  res.json({ success: true, message: "Logged out successfully" });
});

// @desc Forgot Password
// @route POST /api/auth/forgot-password
// @access Public
export const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) throw new Error("User not found");

  const resetToken = user.getResetPasswordToken();
  await user.save({ validateBeforeSave: false });

  const resetUrl = `${process.env.FRONTEND_URL}/auth/reset-password/${resetToken}`;
  const message = `
    <p>Hi ${user.name},</p>
    <p>Click below to reset your password:</p>
    <a href="${resetUrl}">${resetUrl}</a>
    <p>This link expires in 10 minutes.</p>
  `;

  try {
    await sendEmail({
      to: user.email,
      subject: "Password Reset Request",
      html: message,
    });
    res.json({ success: true, message: "Reset link sent to your email" });
  } catch (err) {
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save({ validateBeforeSave: false });
    throw new Error("Email could not be sent");
  }
});

// @desc Reset Password
// @route PUT /api/auth/reset-password/:token
// @access Public
export const resetPassword = asyncHandler(async (req, res) => {
  const resetPasswordToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    resetPasswordToken,
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user) throw new Error("Invalid or expired token");

  user.password = req.body.password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;
  await user.save();

  res.json({ success: true, message: "Password reset successful" });
});
