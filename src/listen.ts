import app from "./app"; 
import dotenv from "dotenv"
import db from "./config/db"

const ENV = process.env.NODE_ENV || "development";
dotenv.config({ path: `${__dirname}/../.env.${ENV}` });

const PORT: number = Number(process.env.PORT) || 3000;

(async () => {
    try {
        const client = await db.connect();
        await client.query("SELECT NOW()");
        client.release();
        console.log("✅ Connected to PostgreSQL");

        app.listen(PORT, () => {
            console.log(`Memberspace running in ${ENV} mode on port ${PORT}...`);
        });
        
    } catch (err) {
        console.error("❌ Failed to connect to the database:", err);
        process.exit(1);
    }
})