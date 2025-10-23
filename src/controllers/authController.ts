import { Request, Response, NextFunction } from 'express';
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import db from "../config/db";

const JWT_SECRET = process.env.JWT_SECRET!;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;

export const register = async (req: Request, res: Response, next: NextFunction) => {
    const { email, password, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    // Check if user already exists
    const existing = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const result = await db.query(
      "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, email, role",
      [email, hashedPassword, role || "user"]
    );

    const user = result.rows[0];

    res.status(201).json({ message: "User registered", user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

export const login = async (req: Request, res: Response, next: NextFunction) => {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.status(400).json({ message: "Invalid credentials" });

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ message: "Invalid credentials" });

    // Access token (short-lived)
    const accessToken = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "15m" });

    // Refresh token (long-lived)
    const refreshToken = jwt.sign({ id: user.id }, JWT_REFRESH_SECRET, { expiresIn: "30d" });

    // Save refresh token in DB
    await db.query(
      "INSERT INTO tokens (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '30 days')",
      [user.id, refreshToken]
    );

    // Set cookies
    res
      .cookie("access_token", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 15 * 60 * 1000,
        sameSite: "lax",
      })
      .cookie("refresh_token", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 30 * 24 * 60 * 60 * 1000,
        sameSite: "lax",
      })
      .json({ message: "Logged in", user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

export const logout = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const refreshTokenFromCookie = req.cookies.refresh_token
        if(refreshTokenFromCookie) {
        await db.query("DELETE FROM tokens WHERE token = $1", [refreshTokenFromCookie]);
        }
        res
        .clearCookie("access_token")
        .clearCookie("refresh_token")
        .json({ message: "Logged out" })
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
};

export const verify = async (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies.access_token
        if (!token) {
            return res.status(401).json({ valid: false, message: "No refresh token found" });
          }
    try {
        const decoded = jwt.verify(token, JWT_SECRET)

        res.status(200).json({
            valid: true,
            user: { id: (decoded as any).id, role: (decoded as any).role }
          });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
};

export const refresh = async (req: Request, res: Response, next: NextFunction) => {
    const refreshToken = req.cookies.refresh_token
    if (!refreshToken) {
        return res
        .clearCookie("access_token")
        .clearCookie("refresh_token")
        .status(401).json({ valid: false, message: "No token found" });
      }
try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET)
    const id = (decoded as any).id
    
    const result = await db.query("SELECT * FROM tokens WHERE token = $1", [refreshToken])
    if (result.rows.length === 0) {
        return res
        .clearCookie("access_token")
        .clearCookie("refresh_token")
        .status(401).json({ valid: false, message: "No refresh token found" });
    }
    const userQuery = await db.query("SELECT * FROM users WHERE id = $1", [id])
    const user = userQuery.rows[0]
    if (!user) {
        res.clearCookie("access_token").clearCookie("refresh_token");
        return res.status(401).json({ valid: false, message: "User not found" });
      }
    const accessToken = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "15m" });
    res
    .cookie("access_token", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 15 * 60 * 1000,
        sameSite: "lax",
      })
      .json({ message: "Session Refreshed", user: { id: user.id, email: user.email, role: user.role } });
} catch (err: any) {
    if (err.name === "TokenExpiredError" || err.name === "JsonWebTokenError") {
        return res.status(401).json({ valid: false, message: "Invalid or expired token" });
      }
      console.error(err);
      res.status(500).json({ message: "Server error" });
  }
};