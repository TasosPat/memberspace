import express from "express";
import { register, login, logout, verify, refresh } from "../controllers/authController";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.get("/verify", verify);
router.get("/refresh", refresh);
router.post("/logout", logout);

export default router;
