import request from "supertest";
import app from "../src/app";
import db from "../src/config/db";
import seed from "../src/db/seed"

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
  });

  it("should refresh session using refresh_token cookie", async () => {
    const res = await agent.get("/auth/refresh");
    expect(res.status).toBe(200);
    expect(res.body.message).toBe("Session Refreshed");
    expect(res.body.user.email).toBe("user@memberspace.dev");
  });

  it("should logout and clear cookies", async () => {
    const res = await agent.post("/auth/logout");
    expect(res.status).toBe(200);
    expect(res.body.message).toBe("Logged out");
  });

  it("should fail login with wrong password", async () => {
    const res = await request(app)
      .post("/auth/login")
      .send({ email: "user@memberspace.dev", password: "wrongpassword" });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe("Invalid credentials");
  });

  it("should fail verify without access_token cookie", async () => {
    const res = await request(app).get("/auth/verify");
    expect(res.status).toBe(401);
    expect(res.body.valid).toBe(false);
  });
});
