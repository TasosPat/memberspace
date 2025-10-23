import express, { Application, Request, Response, NextFunction } from "express";
import cors from "cors"
import authRoutes from "./routes/authRoutes";
import cookieParser from "cookie-parser";

const app: Application = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());

app.get("/", (req: Request, res: Response) => {
  res.status(200).send({ msg: "Memberspace is running 🚀" });
});

app.use("/auth", authRoutes);

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    console.error("Unhandled error:", err);
    res.status(500).json({ message: "Internal Server Error" });
  });

export default app;