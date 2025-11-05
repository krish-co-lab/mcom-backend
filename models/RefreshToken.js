import mongoose from "mongoose";

const refreshTokenSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    token: { type: String, required: true },
    expiresAt: { type: Date, required: true, index: { expires: 0 } },
    // ✅ TTL Index: MongoDB auto-deletes document when expiresAt < now
    userAgent: { type: String }, // Optional: track browser/device
    ip: { type: String }, // Optional: track IP address
  },
  { timestamps: true }
);

// Optional: Prevent duplicate active refresh tokens for the same user/token
refreshTokenSchema.index({ user: 1, token: 1 }, { unique: true });

export default mongoose.model("RefreshToken", refreshTokenSchema);
