import { Request, Response, NextFunction } from "express";

export const verifyApiKey = (req: Request, res: Response, next: NextFunction) => {
    const apiKey = req.headers["x-api-key"];
    if (apiKey !== process.env.MEMBERS_API_KEY) {
      return res.status(403).json({ message: "Forbidden: invalid API key" });
    }
    next();
  };
  