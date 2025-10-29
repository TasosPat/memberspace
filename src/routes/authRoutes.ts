import express from "express";
import { register, login, logout, verify, refresh, verifyEmail, requestPasswordReset, resetPassword, validateToken } from "../controllers/authController";
import { authenticate } from "../middleware/authorise";
import { verifyApiKey } from "../middleware/verifyApiKey";


const router = express.Router();

//frontend to auth calls
router.post("/register", register);
router.post("/login", login);
router.get("/verify-email", verifyEmail);
router.post("/request-password-reset", requestPasswordReset);
router.post("/reset-password", resetPassword);
router.post("/logout", authenticate, logout);

//backend to auth calls
router.get("/refresh", verifyApiKey, refresh);
router.get("/verify", verifyApiKey, authenticate, verify);
router.post("/validate-token", verifyApiKey, validateToken);

export default router;
