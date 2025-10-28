import { Request } from "express";

export type UserRole = "user" | "staff" | "admin";

export interface AuthRequest extends Request {
    user?: {
        id: string;
        email: string;
        role: UserRole
      };
}

export interface JwtPayload {
  id: string;
  email: string;
  role: UserRole
  iat?: number;
  exp?: number;
}