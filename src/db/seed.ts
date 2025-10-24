import bcrypt from "bcrypt";
import db from "../config/db";

async function seed() {
  try {
    console.log("Seeding database...");

    // Drop existing tables (order matters due to FK constraints)
    await db.query(`DROP TABLE IF EXISTS tokens CASCADE;`);
    await db.query(`DROP TABLE IF EXISTS users CASCADE;`);

    // Create users table
    await db.query(`
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user' CHECK (role IN ('user','staff','admin')),
        verified BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Create tokens table
    await db.query(`
      CREATE TABLE tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(500) NOT NULL,
        type VARCHAR(50) DEFAULT 'refresh',
        used BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP
      );
    `);

    // Hash a default password for all users
    const password = await bcrypt.hash("password123", 10);

    // Insert test users
    await db.query(
      `
      INSERT INTO users (email, password_hash, role, verified)
      VALUES
        ('admin@memberspace.dev', $1, 'admin', true),
        ('staff@memberspace.dev', $1, 'staff', true),
        ('user@memberspace.dev', $1, 'user', true);
    `,
      [password]
    );

    console.log("✅ Seeding completed successfully");
  } catch (err) {
    console.error("❌ Error during seeding:", err);
  }
}

export default seed;
