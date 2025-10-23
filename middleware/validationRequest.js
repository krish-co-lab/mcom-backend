// middleware/validateRequest.js
import { validationResult } from "express-validator";

/**
 * Middleware to handle validation results from express-validator.
 * If validation errors exist, it stops the request and responds with 400.
 */
export const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const extractedErrors = errors.array().map((err) => ({
      field: err.path,
      message: err.msg,
    }));

    return res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: extractedErrors,
    });
  }
  next();
};
