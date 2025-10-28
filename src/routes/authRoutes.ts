import express from "express";
import { register, login, logout, verify, refresh, verifyEmail, requestPasswordReset, resetPassword } from "../controllers/authController";
import { authenticate } from "../middleware/authorise";


const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.get("/verify-email", verifyEmail);
router.post("/request-password-reset", requestPasswordReset);
router.post("/reset-password", resetPassword);
router.get("/refresh", refresh);

router.get("/verify", authenticate, verify);
router.post("/logout", authenticate, logout);

export default router;
