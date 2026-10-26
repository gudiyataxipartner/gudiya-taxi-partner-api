require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");
const Razorpay = require("razorpay");
const twilio = require("twilio");
const bcrypt = require("bcryptjs");

const app = express();
const dutyEventClients = new Set();
function broadcastDutyUpdate() {
  const payload = 'event: duty-update\ndata: {"type":"duties-changed"}\n\n';
  for (const client of dutyEventClients) {
    try {
      client.write(payload);
    } catch (_) {
      dutyEventClients.delete(client);
    }
  }
}
const port = Number(process.env.PORT || 8080);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: true } : false,
});
const razorpay =
  process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
    ? new Razorpay({
        key_id: process.env.RAZORPAY_KEY_ID,
        key_secret: process.env.RAZORPAY_KEY_SECRET,
      })
    : null;
const twilioClient =
  process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN
    ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
    : null;

app.disable("x-powered-by");
app.use(helmet());
app.use(
  cors({
    origin(origin, callback) {
      // Android WebView local assets can send Origin: null. Allow only that native-app
      // origin plus an explicitly configured web origin; API routes still require auth.
      if (
        !origin ||
        origin === "null" ||
        (process.env.ANDROID_APP_ORIGIN &&
          origin === process.env.ANDROID_APP_ORIGIN)
      )
        return callback(null, true);
      return callback(null, false);
    },
  })
);
// Razorpay signature verification must use the exact raw request body.
// Keep this route before express.json() so the signature is checked correctly.
app.post(
  "/api/payments/razorpay-webhook",
  express.raw({ type: "application/json", limit: "1mb" }),
  async (req, res) => {
    const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
    const signature = req.get("x-razorpay-signature");
    if (!secret || !signature || !Buffer.isBuffer(req.body)) {
      return res.status(400).send("Webhook not configured");
    }

    try {
      const expected = crypto
        .createHmac("sha256", secret)
        .update(req.body)
        .digest("hex");
      const expectedBuffer = Buffer.from(expected, "utf8");
      const signatureBuffer = Buffer.from(signature, "utf8");
      if (
        expectedBuffer.length !== signatureBuffer.length ||
        !crypto.timingSafeEqual(expectedBuffer, signatureBuffer)
      ) {
        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(req.body.toString("utf8"));
      const eventId =
        req.get("x-razorpay-event-id") ||
        crypto.createHash("sha256").update(req.body).digest("hex");
      const eventType = String(event.event || "unknown");
      const sub = event.payload?.subscription?.entity;
      const payment = event.payload?.payment?.entity;
      const subscriptionId = sub?.id || payment?.subscription_id || null;

      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const inserted = await client.query(
          `INSERT INTO webhook_events(event_id,event_type)
           VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING event_id`,
          [eventId, eventType]
        );

        if (!inserted.rowCount) {
          await client.query("COMMIT");
          return res.status(200).json({ received: true, duplicate: true });
        }

        if (subscriptionId) {
          const providerEnd = Number.isFinite(Number(sub?.current_end))
            ? Number(sub.current_end)
            : null;
          const paymentConfirmed =
            eventType === "subscription.charged" ||
            payment?.status === "captured" ||
            Number(sub?.paid_count || 0) > 0;

          if (eventType === "subscription.charged") {
            // Prefer Razorpay's billing-cycle end. The plan_months fallback is
            // used only if the webhook did not include a usable future end time.
            await client.query(
              `UPDATE subscriptions
               SET status='active',
                   provider_payment_id=COALESCE($1, provider_payment_id),
                   current_period_end=CASE
                     WHEN $2::bigint IS NOT NULL
                       AND to_timestamp($2::bigint) > now()
                     THEN to_timestamp($2::bigint)
                     ELSE now() + (COALESCE(plan_months,1)::text || ' months')::interval
                   END,
                   updated_at=now()
               WHERE provider_subscription_id=$3`,
              [payment?.id || null, providerEnd, subscriptionId]
            );
          } else if (eventType === "subscription.activated") {
            // Do not grant membership on activation alone unless Razorpay's
            // payload confirms a successful charge (paid_count or captured payment).
            await client.query(
              `UPDATE subscriptions
               SET status=CASE
                     WHEN $1::boolean THEN 'active'
                     WHEN status='active' AND current_period_end > now() THEN 'active'
                     ELSE 'authenticated'
                   END,
                   current_period_end=CASE
                     WHEN $1::boolean AND $2::bigint IS NOT NULL
                       AND to_timestamp($2::bigint) > now()
                     THEN to_timestamp($2::bigint)
                     WHEN $1::boolean
                       AND (current_period_end IS NULL OR current_period_end <= now())
                     THEN now() + (COALESCE(plan_months,1)::text || ' months')::interval
                     ELSE current_period_end
                   END,
                   updated_at=now()
               WHERE provider_subscription_id=$3`,
              [paymentConfirmed, providerEnd, subscriptionId]
            );
          } else if (eventType === "subscription.authenticated") {
            await client.query(
              `UPDATE subscriptions
               SET status=CASE
                     WHEN status='active' AND current_period_end > now() THEN 'active'
                     ELSE 'authenticated'
                   END,
                   updated_at=now()
               WHERE provider_subscription_id=$1`,
              [subscriptionId]
            );
          } else if (eventType === "subscription.resumed") {
            await client.query(
              `UPDATE subscriptions
               SET status=CASE
                     WHEN $1::boolean AND (
                       ($2::bigint IS NOT NULL AND to_timestamp($2::bigint) > now())
                       OR current_period_end > now()
                     ) THEN 'active'
                     WHEN current_period_end > now() THEN 'active'
                     ELSE 'authenticated'
                   END,
                   current_period_end=CASE
                     WHEN $2::bigint IS NOT NULL
                       AND to_timestamp($2::bigint) > now()
                     THEN to_timestamp($2::bigint)
                     ELSE current_period_end
                   END,
                   updated_at=now()
               WHERE provider_subscription_id=$3`,
              [paymentConfirmed, providerEnd, subscriptionId]
            );
          } else if (
            ["subscription.halted", "subscription.paused"].includes(eventType)
          ) {
            // Preserve access already paid for until its current period ends.
            await client.query(
              `UPDATE subscriptions
               SET status=CASE
                     WHEN current_period_end > now() THEN 'active'
                     ELSE 'halted'
                   END,
                   updated_at=now()
               WHERE provider_subscription_id=$1`,
              [subscriptionId]
            );
          } else if (
            ["subscription.cancelled", "subscription.completed", "subscription.expired"].includes(eventType)
          ) {
            const terminalState =
              eventType === "subscription.cancelled" ? "cancelled" : "expired";
            // Cancellation should not remove access for a period that was already paid.
            await client.query(
              `UPDATE subscriptions
               SET status=CASE
                     WHEN current_period_end > now() THEN 'active'
                     ELSE $1
                   END,
                   updated_at=now()
               WHERE provider_subscription_id=$2`,
              [terminalState, subscriptionId]
            );
          } else if (eventType === "payment.failed") {
            // A failed renewal must not remove access from an already-paid period.
            await client.query(
              `UPDATE subscriptions
               SET status=CASE
                     WHEN current_period_end > now() THEN 'active'
                     ELSE 'failed'
                   END,
                   updated_at=now()
               WHERE provider_subscription_id=$1`,
              [subscriptionId]
            );
          }
        }

        await client.query("COMMIT");
        return res.status(200).json({ received: true });
      } catch (e) {
        await client.query("ROLLBACK").catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    } catch (e) {
      console.error("Razorpay webhook error", e.message);
      return res.status(500).send("Webhook processing failed");
    }
  }
);

app.use(express.json({ limit: "25mb" }));
app.use(
  rateLimit({
    windowMs: 60_000,
    limit: 120,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

function requireConfig() {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32)
    throw new Error(
      "JWT_SECRET must be configured with at least 32 characters"
    );
}
function normalizePhone(phone) {
  const p = String(phone || "").replace(/\D/g, "");
  if (!/^[6-9]\d{9}$/.test(p))
    throw Object.assign(
      new Error("Enter a valid 10-digit Indian mobile number"),
      { status: 400 }
    );
  return p;
}
function requireAuth(req, res, next) {
  try {
    requireConfig();
    const token = (req.get("authorization") || "").replace(/^Bearer\s+/i, "");
    if (!token) return res.status(401).json({ error: "Login required" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    pool
      .query(
        `SELECT s.id, s.user_id, s.device_id, s.revoked_at, u.phone, u.name, u.role_mode, u.driver_verification, u.vendor_verification
      FROM device_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1`,
        [decoded.sid]
      )
      .then((r) => {
        if (!r.rowCount || r.rows[0].revoked_at)
          return res
            .status(401)
            .json({ error: "Session expired. Please log in again." });
        req.auth = r.rows[0];
        pool
          .query("UPDATE device_sessions SET last_seen_at=now() WHERE id=$1", [
            decoded.sid,
          ])
          .catch(() => {});
        next();
      })
      .catch(next);
  } catch (e) {
    res.status(e.status || 401).json({ error: e.message || "Invalid session" });
  }
}
// Live duty updates (SSE) avoid frequent polling from the Android app.
app.get("/api/duties/events", requireAuth, (req, res) => {
  res.status(200);
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.flushHeaders();
  res.write('event: duty-update\ndata: {"type":"connected"}\n\n');
  dutyEventClients.add(res);
  const heartbeat = setInterval(() => {
    try {
      res.write(": keep-alive\n\n");
    } catch (_) {}
  }, 20000);
  req.on("close", () => {
    clearInterval(heartbeat);
    dutyEventClients.delete(res);
  });
});

function requireAdmin(req, res, next) {
  const expected = process.env.ADMIN_API_KEY;
  const supplied = req.get("x-admin-key") || "";
  if (
    !expected ||
    expected.length < 32 ||
    !supplied ||
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))
  ) {
    return res.status(403).json({ error: "Admin access denied" });
  }
  next();
}
function hasActiveMembership(userId) {
  return pool
    .query(
      `SELECT 1 FROM subscriptions WHERE user_id=$1 AND status='active'
    AND current_period_end > now() ORDER BY current_period_end DESC LIMIT 1`,
      [userId]
    )
    .then((r) => !!r.rowCount);
}
function privateDuty(d) {
  return {
    id: d.id,
    pickupCity: d.pickup_city,
    dropCity: d.drop_city,
    vehicleType: d.vehicle_type,
    dutyDate: d.duty_date,
    dutyTime: d.duty_time,
    distanceKm: d.distance_km,
    distanceLabel: d.distance_label,
    rolePostedAs: d.role_posted_as,
    createdAt: d.created_at,
    status: d.status,
    detailsAvailable: false,
    isOwner: d.is_owner === true,
    acceptedByMe: d.accepted_by_me === true,
  };
}
app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, service: "gudiya-taxi-partner-api" });
  } catch (_e) {
    res.status(503).json({ ok: false, error: "database_unavailable" });
  }
});

// Password-based authentication: no OTP. Phone numbers are not verified in this mode.
app.post(
  "/api/auth/password/register",
  rateLimit({ windowMs: 15 * 60_000, limit: 8 }),
  async (req, res, next) => {
    try {
      const phone = normalizePhone(req.body.phone);
      const name = String(req.body.name || "")
        .trim()
        .slice(0, 100);
      const password = String(req.body.password || "");
      const role = String(req.body.roleMode || "both");
      const deviceId = String(req.body.deviceId || "").trim();
      if (name.length < 2)
        return res.status(400).json({ error: "啶呧お啶ㄠぞ 啶ㄠぞ啶� 啶ぐ啷囙" });
      if (password.length < 8 || password.length > 72)
        return res
          .status(400)
          .json({ error: "啶ぞ啶膏さ啶班啶� 啶曕ぎ 啶膏 啶曕ぎ 8 啶呧啷嵿し啶班啶� 啶曕ぞ 啶灌啶ㄠぞ 啶氞ぞ啶灌た啶�" });
      if (!["driver", "vendor", "both"].includes(role))
        return res.status(400).json({ error: "啶啶た啶曕ぞ 啶膏す啷€ 啶氞啶ㄠ啶�" });
      if (deviceId.length < 8 || deviceId.length > 200)
        return res.status(400).json({ error: "啶∴た啶掂ぞ啶囙じ ID 啶膏す啷€ 啶ㄠす啷€啶� 啶灌" });
      requireConfig();
      const passwordHash = await bcrypt.hash(password, 12);
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const existing = await client.query(
          "SELECT id FROM users WHERE phone=$1",
          [phone]
        );
        if (existing.rowCount) {
          await client.query("ROLLBACK");
          return res
            .status(409)
            .json({
              error: "啶囙じ 啶啶ぞ啶囙げ 啶ㄠ啶ぐ 啶曕ぞ 啶呧啶距啶傕 啶す啶侧 啶膏 啶灌啷� 啶侧啶椸た啶� 啶曕ぐ啷囙啷�",
            });
        }
        const created = await client.query(
          `INSERT INTO users(phone,name,role_mode,password_hash) VALUES($1,$2,$3,$4)
        RETURNING id,phone,name,role_mode,driver_verification,vendor_verification`,
          [phone, name, role, passwordHash]
        );
        const user = created.rows[0];
        const sid = crypto.randomUUID();
        await client.query(
          "INSERT INTO device_sessions(id,user_id,device_id) VALUES($1,$2,$3)",
          [sid, user.id, deviceId]
        );
        await client.query("COMMIT");
        const token = jwt.sign(
          { sub: String(user.id), sid },
          process.env.JWT_SECRET,
          { expiresIn: "30d", issuer: "gudiya-taxi-partner-api" }
        );
        return res
          .status(201)
          .json({ token, user, sessionPolicy: "one-active-device" });
      } catch (e) {
        await client.query("ROLLBACK").catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    } catch (e) {
      next(e);
    }
  }
);
app.post(
  "/api/auth/password/login",
  rateLimit({ windowMs: 15 * 60_000, limit: 10 }),
  async (req, res, next) => {
    try {
      const phone = normalizePhone(req.body.phone);
      const password = String(req.body.password || "");
      const deviceId = String(req.body.deviceId || "").trim();
      if (
        !password ||
        password.length > 72 ||
        deviceId.length < 8 ||
        deviceId.length > 200
      )
        return res
          .status(400)
          .json({ error: "啶啶ぞ啶囙げ, 啶ぞ啶膏さ啶班啶� 啶斷ぐ 啶∴た啶掂ぞ啶囙じ 啶溹ぞ啶ㄠ啶距ぐ啷€ 啶膏す啷€ 啶ぐ啷囙" });
      requireConfig();
      const found = await pool.query(
        "SELECT id,phone,name,role_mode,driver_verification,vendor_verification,password_hash FROM users WHERE phone=$1",
        [phone]
      );
      if (
        !found.rowCount ||
        !found.rows[0].password_hash ||
        !(await bcrypt.compare(password, found.rows[0].password_hash))
      )
        return res.status(401).json({ error: "啶啶ぞ啶囙げ 啶ㄠ啶ぐ 啶ぞ 啶ぞ啶膏さ啶班啶� 啶椸げ啶� 啶灌" });
      const user = found.rows[0];
      delete user.password_hash;
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(
          "UPDATE device_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL",
          [user.id]
        );
        const sid = crypto.randomUUID();
        await client.query(
          "INSERT INTO device_sessions(id,user_id,device_id) VALUES($1,$2,$3)",
          [sid, user.id, deviceId]
        );
        await client.query("COMMIT");
        const token = jwt.sign(
          { sub: String(user.id), sid },
          process.env.JWT_SECRET,
          { expiresIn: "30d", issuer: "gudiya-taxi-partner-api" }
        );
        return res.json({ token, user, sessionPolicy: "one-active-device" });
      } catch (e) {
        await client.query("ROLLBACK").catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    } catch (e) {
      next(e);
    }
  }
);

// OTP send: Twilio Verify service required. Never returns a static or predictable OTP.
app.post(
  "/api/auth/otp/send",
  rateLimit({ windowMs: 10 * 60_000, limit: 5 }),
  async (req, res, next) => {
    try {
      const phone = normalizePhone(req.body.phone);
      if (!twilioClient || !process.env.TWILIO_VERIFY_SERVICE_SID)
        return res
          .status(503)
          .json({ error: "OTP provider is not configured yet" });
      await twilioClient.verify.v2
        .services(process.env.TWILIO_VERIFY_SERVICE_SID)
        .verifications.create({ to: "+91" + phone, channel: "sms" });
      res.json({ sent: true, message: "OTP 啶啶� 啶︵た啶ぞ 啶椸く啶� 啶灌" });
    } catch (e) {
      next(e);
    }
  }
);
app.post(
  "/api/auth/otp/verify",
  rateLimit({ windowMs: 10 * 60_000, limit: 8 }),
  async (req, res, next) => {
    try {
      const phone = normalizePhone(req.body.phone),
        code = String(req.body.code || "").trim();
      const deviceId = String(req.body.deviceId || "").trim();
      if (
        !/^\d{4,8}$/.test(code) ||
        deviceId.length < 8 ||
        deviceId.length > 200
      )
        return res.status(400).json({ error: "OTP 啶斷ぐ device ID 啶膏す啷€ 啶ぐ啷囙" });
      if (!twilioClient || !process.env.TWILIO_VERIFY_SERVICE_SID)
        return res
          .status(503)
          .json({ error: "OTP provider is not configured yet" });
      const check = await twilioClient.verify.v2
        .services(process.env.TWILIO_VERIFY_SERVICE_SID)
        .verificationChecks.create({ to: "+91" + phone, code });
      if (check.status !== "approved")
        return res.status(401).json({ error: "OTP 啶椸げ啶� 啶ぞ 啶膏ぎ啶距お啷嵿い 啶灌 啶椸く啶� 啶灌" });
      requireConfig();
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const u = await client.query(
          `INSERT INTO users(phone) VALUES($1) ON CONFLICT(phone) DO UPDATE SET updated_at=now()
        RETURNING id, phone, name, role_mode, driver_verification`,
          [phone]
        );
        const user = u.rows[0];
        await client.query(
          "UPDATE device_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL",
          [user.id]
        );
        const sid = crypto.randomUUID();
        await client.query(
          "INSERT INTO device_sessions(id,user_id,device_id) VALUES($1,$2,$3)",
          [sid, user.id, deviceId]
        );
        await client.query("COMMIT");
        const token = jwt.sign(
          { sub: String(user.id), sid },
          process.env.JWT_SECRET,
          { expiresIn: "30d", issuer: "gudiya-taxi-partner-api" }
        );
        res.json({ token, user, sessionPolicy: "one-active-device" });
      } catch (e) {
        await client.query("ROLLBACK");
        throw e;
      } finally {
        client.release();
      }
    } catch (e) {
      next(e);
    }
  }
);
app.get("/api/me", requireAuth, (req, res) =>
  res.json({
    user: {
      id: req.auth.user_id,
      phone: req.auth.phone,
      name: req.auth.name,
      roleMode: req.auth.role_mode,
      driverVerification: req.auth.driver_verification,
      vendorVerification: req.auth.vendor_verification,
    },
  })
);
app.patch("/api/me", requireAuth, async (req, res, next) => {
  try {
    const name = String(req.body.name || "")
      .trim()
      .slice(0, 100);
    const role = String(req.body.roleMode || "both");
    if (!["driver", "vendor", "both"].includes(role))
      return res.status(400).json({ error: "Invalid role mode" });
    const r = await pool.query(
      `UPDATE users SET name=$1, role_mode=$2, updated_at=now() WHERE id=$3
      RETURNING id,phone,name,role_mode,driver_verification,vendor_verification`,
      [name, role, req.auth.user_id]
    );
    res.json({ user: r.rows[0] });
  } catch (e) {
    next(e);
  }
});
app.post("/api/auth/logout", requireAuth, async (req, res, next) => {
  try {
    await pool.query(
      "UPDATE device_sessions SET revoked_at=now() WHERE id=$1",
      [req.auth.id]
    );
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

// Driver document uploads are encrypted before being stored in PostgreSQL.
// The encryption key is derived from the configured high-entropy JWT_SECRET.
function encryptDocument(value) {
  requireConfig();
  const key = crypto
    .createHash("sha256")
    .update(
      (process.env.DOCUMENT_ENCRYPTION_KEY || process.env.JWT_SECRET) +
        "|taxi-mitra-documents-v1"
    )
    .digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final(),
  ]);
  return JSON.stringify({
    v: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: encrypted.toString("base64"),
  });
}
function decryptDocument(value) {
  requireConfig();
  const blob = JSON.parse(value);
  const key = crypto
    .createHash("sha256")
    .update(
      (process.env.DOCUMENT_ENCRYPTION_KEY || process.env.JWT_SECRET) +
        "|taxi-mitra-documents-v1"
    )
    .digest();
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(blob.iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(blob.tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(blob.data, "base64")),
    decipher.final(),
  ]);
}
app.post("/api/driver-verification", requireAuth, async (req, res, next) => {
  try {
    const category = String(req.body.category || "driver");
    const role = req.auth.role_mode;
    if (category === "driver" && !["driver", "both"].includes(role))
      return res
        .status(403)
        .json({ error: "啶囙じ 啶呧啶距啶傕 啶啶� 啶∴啶班ぞ啶囙さ啶� 啶啶た啶曕ぞ 啶ㄠす啷€啶� 啶灌" });
    if (category === "vendor" && !["vendor", "both"].includes(role))
      return res
        .status(403)
        .json({ error: "啶囙じ 啶呧啶距啶傕 啶啶� 啶掂啶傕ぁ啶� 啶啶た啶曕ぞ 啶ㄠす啷€啶� 啶灌" });
    if (category === "both" && role !== "both")
      return res
        .status(403)
        .json({
          error:
            "啶膏き啷€ 啶︵じ啷嵿い啶距さ啷囙啶监啶� 啶曕 啶侧た啶� 啶∴啶班ぞ啶囙さ啶� 啶斷ぐ 啶掂啶傕ぁ啶� 啶︵啶ㄠ啶� 啶啶た啶曕ぞ 啶掂ぞ啶侧ぞ 啶呧啶距啶傕 啶溹ぐ啷傕ぐ啷€ 啶灌",
        });
    if (!["driver", "vendor", "both"].includes(category))
      return res.status(400).json({ error: "啶膏い啷嵿く啶距お啶� 啶曕ぞ 啶啶班啶距ぐ 啶膏す啷€ 啶ㄠす啷€啶� 啶灌" });
    const docs = Array.isArray(req.body.documents) ? req.body.documents : [];
    if (!docs.length || docs.length > 4)
      return res
        .status(400)
        .json({ error: "啶膏い啷嵿く啶距お啶� 啶曕 啶侧た啶� 啶溹ぐ啷傕ぐ啷€ 啶︵じ啷嵿い啶距さ啷囙啶� 啶溹啶∴ぜ啷囙" });
    const allowed =
      category === "driver"
        ? new Set(["driving_licence", "vehicle_rc", "aadhaar"])
        : category === "vendor"
        ? new Set(["vendor_aadhaar"])
        : new Set([
            "driving_licence",
            "vehicle_rc",
            "aadhaar",
            "vendor_aadhaar",
          ]);
    const seen = new Set();
    const normalized = [];
    for (const d of docs) {
      const type = String(d.documentType || "");
      const mime = String(d.mimeType || "");
      const filename = String(d.fileName || "document").slice(0, 120);
      const base64 = String(d.dataBase64 || "");
      if (!allowed.has(type) || seen.has(type))
        return res
          .status(400)
          .json({ error: "啶︵じ啷嵿い啶距さ啷囙啶� 啶曕ぞ 啶啶班啶距ぐ 啶膏す啷€ 啶ㄠす啷€啶� 啶灌 啶ぞ 啶︵啶灌ぐ啶距く啶� 啶椸く啶� 啶灌" });
      if (!["application/pdf", "image/jpeg", "image/png"].includes(mime))
        return res
          .status(400)
          .json({ error: "啶曕啶掂げ PDF, JPG 啶ぞ PNG 啶ぞ啶囙げ 啶膏啶掂啶曕ぞ啶� 啶灌啶�" });
      const raw = Buffer.from(base64, "base64");
      if (
        !raw.length ||
        raw.length > 4 * 1024 * 1024 ||
        raw.toString("base64").replace(/=+$/, "") !== base64.replace(/=+$/, "")
      )
        return res
          .status(400)
          .json({ error: "啶灌ぐ 啶︵じ啷嵿い啶距さ啷囙啶� 4 MB 啶膏 啶涏啶熰ぞ 啶斷ぐ 啶膏す啷€ 啶ぞ啶囙げ 啶灌啶ㄠぞ 啶氞ぞ啶灌た啶�" });
      seen.add(type);
      normalized.push({
        type,
        mime,
        filename,
        dataBase64: raw.toString("base64"),
      });
    }
    if (
      category === "driver" &&
      (!seen.has("aadhaar") ||
        !seen.has("driving_licence") ||
        !seen.has("vehicle_rc"))
    )
      return res
        .status(400)
        .json({
          error:
            "啶∴啶班ぞ啶囙さ啶� 啶曕 啶侧た啶� Aadhaar, 啶∴啶班ぞ啶囙さ啶苦啶� 啶侧ぞ啶囙じ啷囙啶� 啶斷ぐ 啶掂ぞ啶灌え RC 啶む啶ㄠ啶� 啶溹ぎ啶� 啶曕ぐ啶ㄠぞ 啶溹ぐ啷傕ぐ啷€ 啶灌",
        });
    if (category === "vendor" && !seen.has("vendor_aadhaar"))
      return res
        .status(400)
        .json({ error: "啶掂啶傕ぁ啶� 啶膏い啷嵿く啶距お啶� 啶曕 啶侧た啶� Aadhaar 啶曕ぞ啶班啶� 啶溹ぎ啶� 啶曕ぐ啷囙" });
    if (
      category === "both" &&
      (!seen.has("aadhaar") ||
        !seen.has("driving_licence") ||
        !seen.has("vehicle_rc") ||
        !seen.has("vendor_aadhaar"))
    )
      return res
        .status(400)
        .json({
          error:
            "啶∴啶班ぞ啶囙さ啶� + 啶掂啶傕ぁ啶� 啶曕 啶侧た啶� 啶︵啶ㄠ啶� Aadhaar, 啶∴啶班ぞ啶囙さ啶苦啶� 啶侧ぞ啶囙じ啷囙啶� 啶斷ぐ 啶掂ぞ啶灌え RC 啶溹ぎ啶� 啶曕ぐ啶ㄠぞ 啶溹ぐ啷傕ぐ啷€ 啶灌",
        });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      for (const d of normalized) {
        const encrypted = encryptDocument(d);
        const ref = "encrypted-db:" + crypto.randomUUID();
        await client.query(
          `INSERT INTO driver_documents(user_id,document_type,secure_object_key,status,encrypted_payload)
          VALUES($1,$2,$3,'pending',$4)
          ON CONFLICT(user_id,document_type) DO UPDATE SET secure_object_key=EXCLUDED.secure_object_key,
          status='pending',encrypted_payload=EXCLUDED.encrypted_payload,reviewer_note=NULL,created_at=now(),reviewed_at=NULL`,
          [req.auth.user_id, d.type, ref, encrypted]
        );
      }
      if (category === "both")
        await client.query(
          "UPDATE users SET driver_verification='pending',vendor_verification='pending',updated_at=now() WHERE id=$1",
          [req.auth.user_id]
        );
      else {
        const column =
          category === "driver" ? "driver_verification" : "vendor_verification";
        await client.query(
          `UPDATE users SET ${column}='pending',updated_at=now() WHERE id=$1`,
          [req.auth.user_id]
        );
      }
      await client.query(
        "INSERT INTO audit_log(action,subject_type,subject_id,details) VALUES($1,$2,$3,$4)",
        [
          category + "_verification_submitted",
          "user",
          String(req.auth.user_id),
          JSON.stringify({ documentTypes: normalized.map((d) => d.type) }),
        ]
      );
      await client.query("COMMIT");
      return res
        .status(201)
        .json({
          ok: true,
          category,
          verification: "pending",
          message: "啶︵じ啷嵿い啶距さ啷囙啶� 啶膏啶班啷嵿し啶苦い 啶班啶� 啶膏 啶溹ぎ啶� 啶灌啶�; 啶啶班ざ啶距じ啶ㄠた啶� 啶溹ぞ啶佮 啶ぞ啶曕 啶灌啷�",
        });
    } catch (e) {
      await client.query("ROLLBACK").catch(() => {});
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    next(e);
  }
});
app.get("/api/driver-verification", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query(
      `SELECT document_type,status,reviewer_note,created_at,reviewed_at FROM driver_documents
      WHERE user_id=$1 ORDER BY document_type`,
      [req.auth.user_id]
    );
    const u = await pool.query(
      "SELECT driver_verification,vendor_verification FROM users WHERE id=$1",
      [req.auth.user_id]
    );
    res.json({
      driverVerification: u.rows[0]?.driver_verification || "not_submitted",
      vendorVerification: u.rows[0]?.vendor_verification || "not_submitted",
      documents: r.rows,
    });
  } catch (e) {
    next(e);
  }
});

// Distance is only accepted from a trusted routing backend in a future integration.
// The server deliberately labels any manually supplied estimate as approximate.
app.post("/api/duties", requireAuth, async (req, res, next) => {
  try {
    const pickup = String(req.body.pickupCity || "")
      .trim()
      .slice(0, 120);
    const drop = String(req.body.dropCity || "")
      .trim()
      .slice(0, 120);
    const role = String(req.body.rolePostedAs || "driver");
    const vehicle = String(req.body.vehicleType || "")
      .trim()
      .slice(0, 80);
    if (!pickup || !drop || !vehicle)
      return res
        .status(400)
        .json({ error: "Pickup, drop 啶斷ぐ vehicle 啶溹ぐ啷傕ぐ啷€ 啶灌啶�" });
    if (!["driver", "vendor"].includes(role))
      return res.status(400).json({ error: "Invalid role" });
    if (req.auth.role_mode !== "both" && req.auth.role_mode !== role)
      return res.status(403).json({ error: "啶囙じ 啶啶た啶曕ぞ 啶曕 啶呧え啷佮ぎ啶むた 啶ㄠす啷€啶� 啶灌" });
    const payout =
      req.body.payoutRupees == null || req.body.payoutRupees === ""
        ? null
        : Math.round(Number(req.body.payoutRupees) * 100);
    if (
      payout != null &&
      (!Number.isFinite(payout) || payout < 0 || payout > 100000000)
    )
      return res.status(400).json({ error: "Invalid payout" });
    const r = await pool.query(
      `INSERT INTO duties(user_id,role_posted_as,pickup_city,pickup_address_private,drop_city,drop_address_private,
      vehicle_type,duty_date,duty_time,payout_paise,notes_private,distance_km,distance_label)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,'啶侧啶 啶︵啶班')
      RETURNING id,pickup_city,drop_city,vehicle_type,duty_date,duty_time,distance_km,distance_label,created_at,status`,
      [
        req.auth.user_id,
        role,
        pickup,
        String(req.body.pickupAddress || "").slice(0, 500),
        drop,
        String(req.body.dropAddress || "").slice(0, 500),
        vehicle,
        req.body.dutyDate || null,
        req.body.dutyTime || null,
        payout,
        String(req.body.notes || "").slice(0, 1000),
      ]
    );
    broadcastDutyUpdate();
    res.status(201).json({ duty: r.rows[0] });
  } catch (e) {
    next(e);
  }
});
app.get("/api/duties", requireAuth, async (req, res, next) => {
  try {
    const pickup = String(req.query.pickup || "")
      .trim()
      .slice(0, 120);
    const drop = String(req.query.drop || "")
      .trim()
      .slice(0, 120);
    const r = await pool.query(
      `SELECT d.id,d.user_id,d.role_posted_as,d.pickup_city,d.pickup_address_private,d.drop_city,d.drop_address_private,d.vehicle_type,
      d.duty_date,d.duty_time,d.payout_paise,d.notes_private,d.distance_km,d.distance_label,d.created_at,d.status,
      (d.user_id=$3) AS is_owner, (d.accepted_by_user_id=$3) AS accepted_by_me, u.name AS poster_name, u.phone AS poster_phone
      FROM duties d JOIN users u ON u.id=d.user_id WHERE d.status='open' AND ($1='' OR d.pickup_city ILIKE '%'||$1||'%')
      AND ($2='' OR d.drop_city ILIKE '%'||$2||'%') ORDER BY d.created_at DESC LIMIT 100`,
      [pickup, drop, req.auth.user_id]
    );
    const active = await hasActiveMembership(req.auth.user_id);
    const duties = r.rows.map((d) => {
      const ageMs = Math.max(0, Date.now() - new Date(d.created_at).getTime());
      const secondsRemaining = Math.max(
        0,
        Math.ceil((5 * 60 * 1000 - ageMs) / 1000)
      );
      // Subscribers see full details immediately. Non-subscribers see basic duty info for the first five minutes; full details unlock after five minutes.
      const detailsAvailable = active || secondsRemaining === 0;
      const basic = {
        ...privateDuty(d),
        freeWindowSecondsRemaining: active ? null : secondsRemaining,
        membershipRequiredAfterFreeWindow: !active && secondsRemaining === 0,
      };
      if (detailsAvailable)
        return {
          ...basic,
          posterName: d.poster_name,
          posterPhone: d.poster_phone,
          pickupAddress: d.pickup_address_private,
          dropAddress: d.drop_address_private,
          payoutRupees: d.payout_paise == null ? null : d.payout_paise / 100,
          notes: d.notes_private,
          detailsAvailable: true,
        };
      return basic;
    });
    res.json({
      duties,
      membershipActive: active,
      privateDetailsRule:
        "subscribers see full details immediately; non-subscribers see full details after the first 5 minutes",
    });
  } catch (e) {
    next(e);
  }
});
// A duty can be accepted by only one other logged-in account. The conditional UPDATE
// is atomic, so simultaneous requests cannot reserve the same duty twice.
app.post("/api/duties/:id/accept", requireAuth, async (req, res, next) => {
  try {
    const id = String(req.params.id || "");
    if (!/^\\d+$/.test(id))
      return res.status(400).json({ error: "啶∴啶啶熰 ID 啶膏す啷€ 啶ㄠす啷€啶� 啶灌" });
    if (!["driver", "both"].includes(req.auth.role_mode))
      return res
        .status(403)
        .json({ error: "啶∴啶啶熰 啶膏啶掂啶曕ぞ啶� 啶曕ぐ啶ㄠ 啶曕 啶侧た啶� 啶∴啶班ぞ啶囙さ啶� 啶呧啶距啶傕 啶溹ぐ啷傕ぐ啷€ 啶灌" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        "SELECT id,user_id,status FROM duties WHERE id=$1 FOR UPDATE",
        [id]
      );
      if (!found.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "啶∴啶啶熰 啶ㄠす啷€啶� 啶た啶侧" });
      }
      const duty = found.rows[0];
      if (String(duty.user_id) === String(req.auth.user_id)) {
        await client.query("ROLLBACK");
        return res
          .status(403)
          .json({ error: "啶呧お啶ㄠ 啶∴啶啶熰 啶栢啶� 啶膏啶掂啶曕ぞ啶� 啶ㄠす啷€啶� 啶曕ぐ 啶膏啶む" });
      }
      if (duty.status !== "open") {
        await client.query("ROLLBACK");
        return res
          .status(409)
          .json({
            error: "啶す 啶∴啶啶熰 啶す啶侧 啶灌 啶膏啶掂啶曕ぞ啶� 啶灌 啶氞啶曕 啶灌 啶ぞ 啶夃お啶侧が啷嵿ぇ 啶ㄠす啷€啶� 啶灌",
          });
      }
      const updated = await client.query(
        `UPDATE duties SET status='accepted', accepted_by_user_id=$2
        WHERE id=$1 AND status='open' RETURNING id,pickup_city,drop_city,vehicle_type,duty_date,duty_time,payout_paise,status`,
        [id, req.auth.user_id]
      );
      if (!updated.rowCount) {
        await client.query("ROLLBACK");
        return res
          .status(409)
          .json({ error: "啶す 啶∴啶啶熰 啶曕た啶膏 啶︵啶膏ぐ啷� 啶∴啶班ぞ啶囙さ啶� 啶ㄠ 啶膏啶掂啶曕ぞ啶� 啶曕ぐ 啶侧 啶灌" });
      }
      await client.query("COMMIT");
      broadcastDutyUpdate();
      return res.json({
        duty: updated.rows[0],
        message: "啶∴啶啶熰 啶膏か啶侧い啶距お啷傕ぐ啷嵿さ啶� 啶膏啶掂啶曕ぞ啶� 啶灌 啶椸",
      });
    } catch (e) {
      await client.query("ROLLBACK").catch(() => {});
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    next(e);
  }
});
app.get("/api/duties/accepted", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query(
      `SELECT d.id,d.user_id,d.role_posted_as,d.pickup_city,d.pickup_address_private,d.drop_city,d.drop_address_private,
      d.vehicle_type,d.duty_date,d.duty_time,d.payout_paise,d.notes_private,d.distance_km,d.distance_label,d.created_at,d.status,
      (d.user_id=$1) AS is_owner, (d.accepted_by_user_id=$1) AS accepted_by_me, u.name AS poster_name, u.phone AS poster_phone
      FROM duties d JOIN users u ON u.id=d.user_id WHERE d.accepted_by_user_id=$1 ORDER BY d.created_at DESC LIMIT 100`,
      [req.auth.user_id]
    );
    res.json({
      duties: r.rows.map((d) => ({
        ...privateDuty(d),
        posterName: d.poster_name,
        posterPhone: d.poster_phone,
        pickupAddress: d.pickup_address_private,
        dropAddress: d.drop_address_private,
        payoutRupees: d.payout_paise == null ? null : d.payout_paise / 100,
        notes: d.notes_private,
        detailsAvailable: true,
      })),
    });
  } catch (e) {
    next(e);
  }
});

app.get("/api/duties/mine", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query(
      `SELECT id,role_posted_as,pickup_city,pickup_address_private,drop_city,drop_address_private,vehicle_type,duty_date,duty_time,payout_paise,notes_private,distance_km,distance_label,created_at,status
      FROM duties WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,
      [req.auth.user_id]
    );
    res.json({
      duties: r.rows.map((d) => ({
        ...privateDuty(d),
        rolePostedAs: d.role_posted_as,
        pickupAddress: d.pickup_address_private,
        dropAddress: d.drop_address_private,
        payoutRupees: d.payout_paise == null ? null : d.payout_paise / 100,
        notes: d.notes_private,
        detailsAvailable: true,
      })),
    });
  } catch (e) {
    next(e);
  }
});

// Only creates a Razorpay recurring subscription. Membership is NOT activated here.
app.post("/api/membership/autopay", requireAuth, async (req, res, next) => {
  try {
    const months = Number(req.body.months || 1);
    const plans = {
      1: { amount: 51, planId: process.env.RAZORPAY_MEMBERSHIP_PLAN_1M_ID },
      3: { amount: 151, planId: process.env.RAZORPAY_MEMBERSHIP_PLAN_3M_ID },
      6: { amount: 301, planId: process.env.RAZORPAY_MEMBERSHIP_PLAN_6M_ID },
    };
    const selected = plans[months];
    if (!selected)
      return res
        .status(400)
        .json({ error: "啶膏う啶膏啶い啶� 啶呧さ啶оた 1, 3 啶ぞ 6 啶す啷€啶ㄠ 啶氞啶ㄠ啶�" });
    if (!razorpay || !selected.planId)
      return res
        .status(503)
        .json({
          error:
            "啶氞啶ㄠぞ 啶灌啶� 啶膏う啶膏啶い啶� 啶啶侧ぞ啶� 啶呧き啷€ 啶啶椸い啶距え 啶膏ぐ啷嵿さ啶� 啶ぐ 啶曕啶ㄠ啶ぜ啶苦啶� 啶ㄠす啷€啶� 啶灌啷� 啶呧き啷€ 啶曕啶� 啶啶膏ぞ 啶ㄠす啷€啶� 啶曕啶距イ",
        });
    const existing = await pool.query(
      `SELECT provider_subscription_id,status FROM subscriptions WHERE user_id=$1
      AND plan_months=$2
      AND (
        status IN ('created','authenticated','pending')
        OR (status='active' AND current_period_end > now())
      )
      ORDER BY created_at DESC LIMIT 1`,
      [req.auth.user_id, months]
    );
    if (existing.rowCount && existing.rows[0].provider_subscription_id)
      return res.json({
        subscriptionId: existing.rows[0].provider_subscription_id,
        status: existing.rows[0].status,
      });
    const created = await razorpay.subscriptions.create({
      plan_id: selected.planId,
      total_count: 120,
      quantity: 1,
      customer_notify: 1,
      notes: {
        gudiya_taxi_partner_user_id: String(req.auth.user_id),
        plan_months: String(months),
        amount_rupees: String(selected.amount),
      },
    });
    await pool.query(
      `INSERT INTO subscriptions(user_id,provider_subscription_id,plan_months,amount_rupees,status)
      VALUES($1,$2,$3,$4,'created') ON CONFLICT(provider_subscription_id) DO NOTHING`,
      [req.auth.user_id, created.id, months, selected.amount]
    );
    res
      .status(201)
      .json({
        subscriptionId: created.id,
        status: created.status,
        shortUrl: created.short_url || null,
        planMonths: months,
        amountRupees: selected.amount,
        message:
          "Complete authorization using Razorpay checkout. Membership activates only after a verified payment webhook.",
      });
  } catch (e) {
    next(e);
  }
});
app.get("/api/membership", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query(
      `SELECT status,current_period_end,created_at,plan_months,amount_rupees FROM subscriptions WHERE user_id=$1
      ORDER BY created_at DESC LIMIT 1`,
      [req.auth.user_id]
    );
    res.json({
      plan: "Gudiya Taxi Partner 啶膏う啶膏啶い啶�",
      plans: [
        { months: 1, amountRupees: 51 },
        { months: 3, amountRupees: 151 },
        { months: 6, amountRupees: 301 },
      ],
      autopayOnly: true,
      active: await hasActiveMembership(req.auth.user_id),
      subscription: r.rows[0] || null,
    });
  } catch (e) {
    next(e);
  }
});

// Admin endpoints: protect with a separate high-entropy key configured only on the server.
app.get(
  "/api/admin/documents/pending",
  requireAdmin,
  async (_req, res, next) => {
    try {
      const r =
        await pool.query(`SELECT id,user_id,document_type,status,created_at FROM driver_documents
      WHERE status='pending' ORDER BY created_at ASC LIMIT 200`);
      res.json({ documents: r.rows });
    } catch (e) {
      next(e);
    }
  }
);
app.get(
  "/api/admin/documents/:id/content",
  requireAdmin,
  async (req, res, next) => {
    try {
      const r = await pool.query(
        "SELECT document_type,encrypted_payload FROM driver_documents WHERE id=$1",
        [req.params.id]
      );
      if (!r.rowCount || !r.rows[0].encrypted_payload)
        return res.status(404).json({ error: "Encrypted document not found" });
      const doc = JSON.parse(
        decryptDocument(r.rows[0].encrypted_payload).toString("utf8")
      );
      const bytes = Buffer.from(doc.dataBase64, "base64");
      res.set("Content-Type", doc.mime || "application/octet-stream");
      res.set(
        "Content-Disposition",
        'attachment; filename="' +
          String(doc.filename || "document").replace(/[\r\n"\\]/g, "_") + '"' ); res.set("Cache-Control", "no-store"); res.send(bytes); } catch (e) { next(e); } } ); app.post( "/api/admin/documents/:id/review", requireAdmin, async (req, res, next) => { try { const status = String(req.body.status || ""); if (!["approved", "rejected"].includes(status)) return res .status(400) .json({ error: "status must be approved or rejected" }); const client = await pool.connect(); try { await client.query("BEGIN"); const doc = await client.query( `UPDATE driver_documents SET status=$1,reviewer_note=$2,reviewed_at=now() WHERE id=$3 AND status='pending' RETURNING user_id`, [status, String(req.body.note || "").slice(0, 500), req.params.id] ); if (!doc.rowCount) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Pending document not found" }); } const docType = await client.query( "SELECT document_type FROM driver_documents WHERE id=$1", [req.params.id] ); const category = docType.rows[0]?.document_type?.startsWith("vendor_") ? "vendor" : "driver"; const types = category === "vendor" ? ["vendor_aadhaar"] : ["aadhaar", "driving_licence", "vehicle_rc"]; const pending = await client.query( `SELECT count(*)::int AS n FROM driver_documents WHERE user_id=$1 AND document_type = ANY($2::text[]) AND status='pending'`, [doc.rows[0].user_id, types] ); const rejected = await client.query( `SELECT count(*)::int AS n FROM driver_documents WHERE user_id=$1 AND document_type = ANY($2::text[]) AND status='rejected'`, [doc.rows[0].user_id, types] ); const approved = await client.query( `SELECT count(*)::int AS n FROM driver_documents WHERE user_id=$1 AND document_type = ANY($2::text[]) AND status='approved'`, [doc.rows[0].user_id, types] ); let verify = "pending"; if (Number(rejected.rows[0].n) > 0) verify = "rejected"; else if ( Number(pending.rows[0].n) === 0 && Number(approved.rows[0].n) >= (category === "vendor" ? 1 : 3) ) verify = "approved"; const column = category === "vendor" ? "vendor_verification" : "driver_verification"; await client.query( `UPDATE users SET ${column}=$1,updated_at=now() WHERE id=$2`, [verify, doc.rows[0].user_id] ); await client.query( "INSERT INTO audit_log(action,subject_type,subject_id,details) VALUES($1,$2,$3,$4)", [ category + "_document_review", "driver_document", String(req.params.id), JSON.stringify({ status, verify }), ] ); await client.query("COMMIT"); res.json({ ok: true, category, verification: verify }); } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); } } catch (e) { next(e); } } ); app.use((err, _req, res, _next) => { console.error(err.message); const status = Number(err.status) || 500; res .status(status) .json({ error: status < 500 ? err.message : "Server error" }); }); // Bootstrap the complete schema before accepting requests. This also fixes login's
// generic Server error on a fresh Gudiya database where users/device_sessions did not exist.
// Locate schema.sql whether this file is started from the repository root
// (node server.js) or from the src directory (node src/server.js).
const schemaCandidates = [
  path.join(__dirname, "schema.sql"),
  path.join(__dirname, "..", "schema.sql"),
  path.join(process.cwd(), "schema.sql"),
];
const schemaPath = schemaCandidates.find((candidate) =>
  fs.existsSync(candidate)
);
if (!schemaPath) {
  throw new Error(
    "schema.sql not found. Checked: " + schemaCandidates.join(", ")
  );
}
console.log("Loading database schema from:", schemaPath);
const schemaSql = fs.readFileSync(schemaPath, "utf8");
pool
  .query(schemaSql)
  .then(() =>
    pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT")
  )
  .then(() =>
    pool.query(
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_verification TEXT NOT NULL DEFAULT 'not_submitted'"
    )
  )
  .then(() =>
    pool.query(
      "ALTER TABLE driver_documents ADD COLUMN IF NOT EXISTS encrypted_payload TEXT"
    )
  )
  .then(() =>
    pool.query(
      "ALTER TABLE driver_documents DROP CONSTRAINT IF EXISTS driver_documents_document_type_check"
    )
  )
  .then(() =>
    pool.query(
      "ALTER TABLE driver_documents ADD CONSTRAINT driver_documents_document_type_check CHECK (document_type IN ('aadhaar','vendor_aadhaar','driving_licence','vehicle_rc','vendor_gst','vendor_pan'))"
    )
  )
  .then(() =>
    app.listen(port, () =>
      console.log(`Gudiya Taxi Partner API listening on ${port}`)
    )
  )
  .catch((e) => {
    console.error("Database schema initialization failed:", e.message);
    process.exit(1);
  });
