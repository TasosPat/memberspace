import express from "express";
import { register, login, logout, verify, refresh, verifyEmail, requestPasswordReset, resetPassword } from "../controllers/authController";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.get("/verify", verify);
router.get("/refresh", refresh);
router.post("/logout", logout);
router.get("/verify-email", verifyEmail);
router.post("/request-password-reset", requestPasswordReset);
router.post("/reset-password", resetPassword);

export default router;
