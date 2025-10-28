import { Request, Response, NextFunction } from "express";
import { AuthRequest, JwtPayload } from "../types/index"

import jwt from "jsonwebtoken";

export const authorise = (roles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    const token = req.cookies.access_token;
    if (!token) return res.status(401).json({ message: "No token provided" });

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
      if (!roles.includes(decoded.role)) {
        return res.status(403).json({ message: "Forbidden" });
      }
      req.user = {
        id: decoded.id,
        email: decoded.email,
        role: decoded.role
      };
      next();
    } catch (err: any) {
        const message =
          err.name === "TokenExpiredError" ? "Token expired" : "Invalid token";
        return res.status(401).json({ message });
      }
  };
};

export const authenticate = authorise(["user", "staff", "admin"]);

