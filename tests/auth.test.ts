import request from "supertest";
import app from "../src/app";
import db from "../src/config/db";
import seed from "../src/db/seed";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

beforeAll(async () => {
    await seed();
  });

  afterAll(async () => {
    await db.end();
  });

describe("Auth Endpoints", () => {
    const agent = request.agent(app);
  it("should login successfully and set cookies", async () => {
    const res = await agent
      .post("/auth/login")
      .send({ email: "user@memberspace.dev", password: "password123" });

    expect(res.status).toBe(200);
    expect(res.headers['set-cookie']).toBeDefined(); // access_token & refresh_token
    expect(res.body.user.email).toBe("user@memberspace.dev");
    expect(res.body.user.role).toBe("user");
  });

  it("should verify session with access_token cookie", async () => {
    const res = await agent.get("/auth/verify");
    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
    expect(res.body.user).toHaveProperty("id");
    expect(res.body.user).toHaveProperty("role");
    expect(res.body.user).toHaveProperty("email");
  });

  it("should refresh session using refresh_token cookie", async () => {
    const res = await agent.get("/auth/refresh");
    expect(res.status).toBe(200);
    expect(res.body.message).toBe("Session Refreshed");
    expect(res.body.user.email).toBe("user@memberspace.dev");
  });

  it("should logout and clear cookies, and remove refresh tokens from DB", async () => {
    const res = await agent.post("/auth/logout");
    expect(res.status).toBe(200);
    expect(res.body.message).toBe("Logged out");

    const userRes = await db.query("SELECT id FROM users WHERE email = $1", ["user@memberspace.dev"]);
    const userId = userRes.rows[0].id;
  
    const tokens = await db.query("SELECT * FROM tokens WHERE user_id = $1", [userId]);
    expect(tokens.rowCount).toBe(0);
  });

  it("should return 401 when there are no cookies", async () => {
    const res = await agent.post("/auth/logout");
    expect(res.status).toBe(401);
  });

  it("should fail if no refresh token cookie", async () => {
    const res = await agent.get("/auth/refresh");
    expect(res.status).toBe(401);
    expect(res.body.message).toBe("No token found");
    expect(res.body.valid).toBe(false);
  });

  it("should fail login with wrong password", async () => {
    const res = await request(app)
      .post("/auth/login")
      .send({ email: "user@memberspace.dev", password: "wrongpassword" });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe("Invalid credentials");
  });
  it("should fail login with wrong email", async () => {
    const res = await request(app)
      .post("/auth/login")
      .send({ email: "use1@memberspace.dev", password: "password123" });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe("Invalid credentials");
  });
  it("should fail login if email or password are missing", async () => {
    const res = await request(app)
      .post("/auth/login")
      .send({ email: "user@memberspace.dev" });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe("Email and password required");
  });

  it("should fail verify without access_token cookie", async () => {
    const res = await request(app).get("/auth/verify");
    expect(res.status).toBe(401);
  });
  it("should reject expired access token", async () => {
    // Create token that expired 10 seconds ago
    const expiredToken = jwt.sign(
      { id: 1, email: "user@memberspace.dev", role: "user" },
      process.env.JWT_SECRET!,
      { expiresIn: "-10s" } // <-- this makes it expired in the past
    );

    const res = await request(app)
      .get("/auth/verify")
      .set("Cookie", [`access_token=${expiredToken}`]);

    expect(res.status).toBe(401);
    expect(res.body.message).toMatch(/expired/i);
  });

  it("should fail if refresh token missing from DB", async () => {
    // First: login to get a valid refresh token cookie
    const loginRes = await agent
      .post("/auth/login")
      .send({ email: "user@memberspace.dev", password: "password123" });
    
    expect(loginRes.status).toBe(200);

   // Then: delete that token from the database manually
    
    const cookies = loginRes.headers["set-cookie"];
    const cookieArray = Array.isArray(cookies) ? cookies : [cookies];

    const refreshCookie = cookieArray.find((c: string) =>
    c.startsWith("refresh_token")
);

    const refreshToken = refreshCookie?.split(";")[0].split("=")[1];
  
    await db.query("DELETE FROM tokens WHERE token = $1", [refreshToken]);
  
    // Now: try to refresh with the same cookie (should fail)
    const refreshRes = await agent.get("/auth/refresh");
  
    expect(refreshRes.status).toBe(401);
    expect(refreshRes.body.message).toMatch(/no refresh token/i);
  });

  it("should fail if refresh token invalid or expired", async () => {
    const expiredToken = jwt.sign(
      { id: 1 },
      process.env.JWT_REFRESH_SECRET!,
      { expiresIn: "-10s" } // already expired
    );
  
    const res = await agent
      .get("/auth/refresh")
      .set("Cookie", [`refresh_token=${expiredToken}`]);
  
    expect(res.status).toBe(401);
    expect(res.body.message).toMatch(/invalid|expired/i);
  });
});

describe("Register Endpoint", () => {
  it("should register a new user successfully", async () => {
    const res = await request(app)
      .post("/auth/register")
      .send({
        email: "newuser@memberspace.dev",
        password: "securePassword123",
      });

    expect(res.status).toBe(201);
    expect(res.body.message).toMatch(/registered/i);
    expect(res.body.user).toHaveProperty("email", "newuser@memberspace.dev");

    // Verify DB insertion
    const dbUser = await db.query(
      "SELECT * FROM users WHERE email = $1",
      ["newuser@memberspace.dev"]
    );
    expect(dbUser.rows.length).toBe(1);
    expect(dbUser.rows[0].email).toBe("newuser@memberspace.dev");

    // Verify password is hashed (not stored in plain text)
    const { password_hash } = dbUser.rows[0];
    const match = await bcrypt.compare("securePassword123", password_hash);
    expect(match).toBe(true);
    expect(password_hash).not.toBe("securePassword123");

    // Check token was created in DB
    const tokenResult = await db.query(
      "SELECT * FROM tokens t JOIN users u ON t.user_id = u.id WHERE u.email = $1 AND t.type = 'verification'",
      ["newuser@memberspace.dev"]
    );
    expect(tokenResult.rows.length).toBe(1);
  });

  it("should fail to register with duplicate email", async () => {
    const res = await request(app)
      .post("/auth/register")
      .send({
        email: "user@memberspace.dev", // already exists from seed
        password: "password123",
      });

    expect(res.status).toBe(409);
    expect(res.body.message).toMatch(/already exists/i);
  });

  it("should fail if email or password missing", async () => {
    const res = await request(app)
      .post("/auth/register")
      .send({ email: "incomplete@memberspace.dev" });

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/Email and password are required/i);
  });

  it("should not verify with invalid token", async () => {
    const res = await request(app).get(`/auth/verify-email?token=invalidtoken`);
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/invalid or expired token/i);
  });

  it("should verify email successfully with valid token", async () => {
    // Get the token from DB
    const tokenResult = await db.query(
      "SELECT * FROM tokens t JOIN users u ON t.user_id = u.id WHERE u.email = $1 AND t.type = 'verification'",
      ["newuser@memberspace.dev"]
    );
    const token = tokenResult.rows[0].token;

    const res = await request(app).get(`/auth/verify-email?token=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/verified/i);

    // Confirm user is marked verified
    const userResult = await db.query(
      "SELECT verified FROM users WHERE email = $1",
      ["newuser@memberspace.dev"]
    );
    expect(userResult.rows[0].verified).toBe(true);
  });
});

describe("Password Reset Flow", () => {
  it("should fail if no email is provided", async () => {
    const res = await request(app).post("/auth/request-password-reset").send({ email: ""});
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/email required/i);
  });

  it("should fail if email does not exist", async () => {
    const res = await request(app)
      .post("/auth/request-password-reset")
      .send({ email: "unknown@memberspace.dev" });
    expect(res.status).toBe(404);
    expect(res.body.message).toMatch(/user not found/i);
  });

  it("should create password reset token for existing user", async () => {
    const res = await request(app)
      .post("/auth/request-password-reset")
      .send({ email: "newuser@memberspace.dev" });
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/Password reset email sent/i);

    // Verify token exists in DB
    const tokenResult = await db.query(
      "SELECT * FROM tokens t JOIN users u ON t.user_id = u.id WHERE u.email = $1 AND t.type = 'password_reset'",
      ["newuser@memberspace.dev"]
    );
    expect(tokenResult.rows.length).toBe(1);
  });

  it("should fail if token is invalid or expired", async () => {
    const res = await request(app)
      .post("/auth/reset-password")
      .send({ token: "invalidtoken", newPassword: "newpass123" });
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/invalid or expired token/i);
  });

  it("should reset password successfully with valid token", async () => {
    // Get valid reset token from DB
    const tokenResult = await db.query(
      "SELECT * FROM tokens t JOIN users u ON t.user_id = u.id WHERE u.email = $1 AND t.type = 'password_reset'",
      ["newuser@memberspace.dev"]
    );
    const token = tokenResult.rows[0].token;

    const res = await request(app)
      .post("/auth/reset-password")
      .send({ token, newPassword: "newpassword123" });

    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/password reset successfully/i);

    // Token should be marked used
    const updatedToken = await db.query("SELECT used FROM tokens WHERE token = $1", [token]);
    expect(updatedToken.rows[0].used).toBe(true);
  });
  it("should not allow password reset with used token", async () => {
    const tokenResult = await db.query(
      "SELECT * FROM tokens WHERE used = true AND type = 'password_reset' AND expires_at > NOW()"
    );
    const token = tokenResult.rows[0].token;

    const res = await request(app)
      .post("/auth/reset-password")
      .send({ token, newPassword: "newpassword1234" });

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/Invalid or expired token/i);
  });

  it("should reject expired access token for email verification", async () => {
    const userRes = await db.query("SELECT id FROM users WHERE email = $1", ["newuser@memberspace.dev"]);
    const userId = userRes.rows[0].id;
  
    const expiredToken = "expired-verification-token";
    await db.query(
      "INSERT INTO tokens (user_id, token, type, expires_at) VALUES ($1, $2, $3, NOW() - INTERVAL '1 minute')",
      [userId, expiredToken, "verification"]
    );

    const res = await request(app)
      .get(`/auth/verify-email?token=${expiredToken}`)

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/expired/i);
  });
});