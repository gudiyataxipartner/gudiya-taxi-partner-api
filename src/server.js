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
const bcrypt = require("bcryptjs");
const firebaseAdmin = require("firebase-admin");

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

// Firebase Admin credentials must be stored as a Render secret, never committed to GitHub.
// Set FIREBASE_SERVICE_ACCOUNT_JSON to the complete service-account JSON string.
let firebaseMessaging = null;
try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    const serviceAccount = JSON.parse(
      process.env.FIREBASE_SERVICE_ACCOUNT_JSON
    );
    if (!firebaseAdmin.apps.length) {
      firebaseAdmin.initializeApp({
        credential: firebaseAdmin.credential.cert(serviceAccount),
      });
    }
    firebaseMessaging = firebaseAdmin.messaging();
  }
} catch (error) {
  console.error(
    "Firebase Admin is not configured; push notifications are disabled:",
    error.message
  );
}

async function sendPushToUserIds(userIds, title, body, extraData = {}) {
  if (!firebaseMessaging || !Array.isArray(userIds) || !userIds.length) return;
  try {
    const ids = [...new Set(userIds.map(String))];
    const found = await pool.query(
      "SELECT token FROM push_tokens WHERE user_id = ANY($1::bigint[])",
      [ids]
    );
    const tokens = found.rows.map((row) => row.token).filter(Boolean);
    for (let i = 0; i < tokens.length; i += 500) {
      const batch = tokens.slice(i, i + 500);
      const data = Object.fromEntries(
        Object.entries({
          title,
          body,
          ...extraData,
        }).map(([key, value]) => [key, String(value ?? "")])
      );
      const result = await firebaseMessaging.sendEachForMulticast({
        tokens: batch,
        data,
        android: { priority: "high" },
      });
      const invalid = [];
      result.responses.forEach((response, index) => {
        if (
          !response.success &&
          [
            "messaging/registration-token-not-registered",
            "messaging/invalid-registration-token",
          ].includes(response.error?.code)
        )
          invalid.push(batch[index]);
      });
      if (invalid.length)
        await pool.query(
          "DELETE FROM push_tokens WHERE token = ANY($1::text[])",
          [invalid]
        );
    }
  } catch (error) {
    console.error("Push notification send failed:", error.message);
  }
}

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
// Razorpay signature needs the exact raw request body. Parse JSON only after webhook route.
app.post(
  "/api/payments/razorpay-webhook",
  express.raw({ type: "application/json", limit: "1mb" }),
  async (req, res) => {
    const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
    const signature = req.get("x-razorpay-signature");
    if (!secret || !signature || !Buffer.isBuffer(req.body))
      return res.status(400).send("Webhook not configured");
    try {
      const expected = crypto
        .createHmac("sha256", secret)
        .update(req.body)
        .digest("hex");
      const a = Buffer.from(expected, "utf8"),
        b = Buffer.from(signature, "utf8");
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b))
        return res.status(400).send("Invalid signature");
      const event = JSON.parse(req.body.toString("utf8"));
      const eventId =
        req.get("x-razorpay-event-id") ||
        crypto.createHash("sha256").update(req.body).digest("hex");
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const inserted = await client.query(
          "INSERT INTO webhook_events(event_id,event_type) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING event_id",
          [eventId, event.event || "unknown"]
        );
        if (!inserted.rowCount) {
          await client.query("COMMIT");
          return res.status(200).json({ received: true, duplicate: true });
        }
        const sub = event.payload?.subscription?.entity;
        const payment = event.payload?.payment?.entity;
        const subscriptionId = sub?.id || payment?.subscription_id;
        if (subscriptionId) {
          
if (
  ["subscription.activated", "subscription.authenticated"].includes(
    event.event
  )
) {
  await client.query(
    `UPDATE subscriptions
     SET status = CASE
       WHEN status = 'active'
            AND current_period_end > now()
            AND provider_payment_id IS NOT NULL
       THEN 'active'
       ELSE 'authenticated'
     END,
     updated_at = now()
     WHERE provider_subscription_id = $1`,
    [subscriptionId]
  );
} else if (
  event.event === "subscription.charged" &&
  payment?.id &&
  payment?.status === "captured"
) {
  await client.query(
    `UPDATE subscriptions
     SET status = 'active',
         provider_payment_id = COALESCE($1, provider_payment_id),
         current_period_end = CASE
           WHEN $2::bigint IS NOT NULL
                AND to_timestamp($2::bigint) > now()
           THEN to_timestamp($2::bigint)
           ELSE now() + (COALESCE(plan_months, 1)::text || ' months')::interval
         END,
         updated_at = now()
     WHERE provider_subscription_id = $3`,
    [payment?.id || null, sub?.current_end || null, subscriptionId]
  );
} else if (
  ["subscription.halted", "subscription.cancelled", "subscription.completed"].includes(
    event.event
  )
) {
  const state =
    event.event === "subscription.cancelled" ||
    event.event === "subscription.completed"
      ? "cancelled"
      : "halted";

  await client.query(
    `UPDATE subscriptions
     SET status = CASE
       WHEN current_period_end > now()
            AND provider_payment_id IS NOT NULL
       THEN 'active'
       ELSE $1
     END,
     updated_at = now()
     WHERE provider_subscription_id = $2`,
    [state, subscriptionId]
  );
} else if (event.event === "payment.failed") {
  await client.query(
    `UPDATE subscriptions
     SET status = CASE
       WHEN current_period_end > now()
            AND provider_payment_id IS NOT NULL
       THEN 'active'
       ELSE 'failed'
     END,
     updated_at = now()
     WHERE provider_subscription_id = $1`,
    [subscriptionId]
  );
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
        return res.status(400).json({ error: "अपना नाम भरें" });
      if (password.length < 8 || password.length > 72)
        return res
          .status(400)
          .json({ error: "पासवर्ड कम से कम 8 अक्षरों का होना चाहिए" });
      if (!["driver", "vendor", "both"].includes(role))
        return res.status(400).json({ error: "भूमिका सही चुनें" });
      if (deviceId.length < 8 || deviceId.length > 200)
        return res.status(400).json({ error: "डिवाइस ID सही नहीं है" });
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
              error: "इस मोबाइल नंबर का अकाउंट पहले से है। लॉगिन करें।",
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
          .json({ error: "मोबाइल, पासवर्ड और डिवाइस जानकारी सही भरें" });
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
        return res.status(401).json({ error: "मोबाइल नंबर या पासवर्ड गलत है" });
      const user = found.rows[0];
      delete user.password_hash;
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(
          "UPDATE device_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL",
          [user.id]
        );
        await client.query("DELETE FROM push_tokens WHERE user_id=$1", [
          user.id,
        ]);
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
app.post("/api/push/register-token", requireAuth, async (req, res, next) => {
  try {
    const token = String(req.body.token || "").trim();
    if (token.length < 20 || token.length > 4096 || /\\s/.test(token)) {
      return res.status(400).json({ error: "Invalid push token" });
    }
    await pool.query(
      `INSERT INTO push_tokens(token,user_id,created_at,last_seen_at)
      VALUES($1,$2,now(),now())
      ON CONFLICT(token) DO UPDATE SET user_id=EXCLUDED.user_id,last_seen_at=now()`,
      [token, req.auth.user_id]
    );
    return res.json({ ok: true, registered: true });
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
    await pool.query("DELETE FROM push_tokens WHERE user_id=$1", [
      req.auth.user_id,
    ]);
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
        .json({ error: "इस अकाउंट में ड्राइवर भूमिका नहीं है" });
    if (category === "vendor" && !["vendor", "both"].includes(role))
      return res
        .status(403)
        .json({ error: "इस अकाउंट में वेंडर भूमिका नहीं है" });
    if (category === "both" && role !== "both")
      return res
        .status(403)
        .json({
          error:
            "सभी दस्तावेज़ों के लिए ड्राइवर और वेंडर दोनों भूमिका वाला अकाउंट जरूरी है",
        });
    if (!["driver", "vendor", "both"].includes(category))
      return res.status(400).json({ error: "सत्यापन का प्रकार सही नहीं है" });
    const docs = Array.isArray(req.body.documents) ? req.body.documents : [];
    if (!docs.length || docs.length > 4)
      return res
        .status(400)
        .json({ error: "सत्यापन के लिए जरूरी दस्तावेज़ जोड़ें" });
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
          .json({ error: "दस्तावेज़ का प्रकार सही नहीं है या दोहराया गया है" });
      if (!["application/pdf", "image/jpeg", "image/png"].includes(mime))
        return res
          .status(400)
          .json({ error: "केवल PDF, JPG या PNG फाइल स्वीकार हैं" });
      const raw = Buffer.from(base64, "base64");
      if (
        !raw.length ||
        raw.length > 4 * 1024 * 1024 ||
        raw.toString("base64").replace(/=+$/, "") !== base64.replace(/=+$/, "")
      )
        return res
          .status(400)
          .json({ error: "हर दस्तावेज़ 4 MB से छोटा और सही फाइल होना चाहिए" });
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
            "ड्राइवर के लिए Aadhaar, ड्राइविंग लाइसेंस और वाहन RC तीनों जमा करना जरूरी है",
        });
    if (category === "vendor" && !seen.has("vendor_aadhaar"))
      return res
        .status(400)
        .json({ error: "वेंडर सत्यापन के लिए Aadhaar कार्ड जमा करें" });
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
            "ड्राइवर + वेंडर के लिए दोनों Aadhaar, ड्राइविंग लाइसेंस और वाहन RC जमा करना जरूरी है",
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
          message: "दस्तावेज़ सुरक्षित रूप से जमा हुए; प्रशासनिक जाँच बाकी है।",
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
        .json({ error: "Pickup, drop और vehicle जरूरी हैं" });
    if (!["driver", "vendor"].includes(role))
      return res.status(400).json({ error: "Invalid role" });
    if (req.auth.role_mode !== "both" && req.auth.role_mode !== role)
      return res.status(403).json({ error: "इस भूमिका की अनुमति नहीं है" });
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
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,'लगभग दूरी')
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
    const targetRole = role === "vendor" ? "driver" : "vendor";
    pool
      .query(
        "SELECT id FROM users WHERE id<>$1 AND (role_mode=$2 OR role_mode='both')",
        [req.auth.user_id, targetRole]
      )
      .then((rows) =>
        sendPushToUserIds(
          rows.rows.map((row) => row.id),
          "नई ड्यूटी उपलब्ध है",
          `${pickup} से ${drop} के लिए नई ड्यूटी पोस्ट हुई है।`,
          { type: "new_duty", dutyId: r.rows[0].id }
        )
      )
      .catch((error) =>
        console.error("Could not find push recipients:", error.message)
      );
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
      // The person who posted a duty always sees its full details, regardless of membership.
      // Other subscribers see full details immediately; other non-subscribers unlock them after five minutes.
      // Compare IDs as strings too, so the duty poster is never locked by a boolean/type mismatch.
      const isOwner =
        d.is_owner === true || String(d.user_id) === String(req.auth.user_id);
      const detailsAvailable = isOwner || active || secondsRemaining === 0;
      const basic = {
        ...privateDuty(d),
        isOwner,
        detailsAvailable,
        freeWindowSecondsRemaining: isOwner || active ? null : secondsRemaining,
        membershipRequiredAfterFreeWindow:
          !isOwner && !active && secondsRemaining === 0,
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
        "duty owner always sees full details; subscribers see full details immediately; other non-subscribers see full details after the first 5 minutes",
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
    if (!/^\d+$/.test(id))
      return res.status(400).json({ error: "ड्यूटी ID सही नहीं है" });
    if (!["driver", "both"].includes(req.auth.role_mode))
      return res
        .status(403)
        .json({ error: "ड्यूटी स्वीकार करने के लिए ड्राइवर अकाउंट जरूरी है" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        "SELECT id,user_id,status FROM duties WHERE id=$1 FOR UPDATE",
        [id]
      );
      if (!found.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "ड्यूटी नहीं मिली" });
      }
      const duty = found.rows[0];
      if (String(duty.user_id) === String(req.auth.user_id)) {
        await client.query("ROLLBACK");
        return res
          .status(403)
          .json({ error: "अपनी ड्यूटी खुद स्वीकार नहीं कर सकते" });
      }
      if (duty.status !== "open") {
        await client.query("ROLLBACK");
        return res
          .status(409)
          .json({
            error: "यह ड्यूटी पहले ही स्वीकार हो चुकी है या उपलब्ध नहीं है",
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
          .json({ error: "यह ड्यूटी किसी दूसरे ड्राइवर ने स्वीकार कर ली है" });
      }
      await client.query("COMMIT");
      broadcastDutyUpdate();
      void sendPushToUserIds(
        [duty.user_id],
        "ड्यूटी स्वीकार हुई",
        `${updated.rows[0].pickup_city} से ${updated.rows[0].drop_city} की ड्यूटी स्वीकार कर ली गई है।`,
        { type: "duty_accepted", dutyId: updated.rows[0].id }
      );
      return res.json({
        duty: updated.rows[0],
        message: "ड्यूटी सफलतापूर्वक स्वीकार हो गई",
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
// Only the user who posted the duty can mark it booked. This also supports bookings confirmed by phone/WhatsApp while status is still open.
app.post("/api/duties/:id/booked", requireAuth, async (req, res, next) => {
  try {
    const id = String(req.params.id || "");
    if (!/^\d+$/.test(id))
      return res.status(400).json({ error: "ड्यूटी ID सही नहीं है" });
    const r = await pool.query(
      `UPDATE duties SET status='booked'
      WHERE id=$1 AND user_id=$2 AND status IN ('open','accepted')
      RETURNING id,pickup_city,drop_city,status,accepted_by_user_id`,
      [id, req.auth.user_id]
    );
    if (!r.rowCount) {
      const existing = await pool.query(
        "SELECT user_id,status FROM duties WHERE id=$1",
        [id]
      );
      if (!existing.rowCount)
        return res.status(404).json({ error: "ड्यूटी नहीं मिली" });
      if (String(existing.rows[0].user_id) !== String(req.auth.user_id))
        return res
          .status(403)
          .json({ error: "केवल ड्यूटी डालने वाला ही DUTY BOOKED कर सकता है" });
      return res
        .status(409)
        .json({ error: "यह ड्यूटी पहले ही बुक, पूरी या रद्द हो चुकी है" });
    }
    broadcastDutyUpdate();
    if (r.rows[0].accepted_by_user_id) {
      void sendPushToUserIds(
        [r.rows[0].accepted_by_user_id],
        "DUTY BOOKED",
        `${r.rows[0].pickup_city} से ${r.rows[0].drop_city} की ड्यूटी बुक कन्फर्म हो गई है।`,
        { type: "duty_booked", dutyId: r.rows[0].id }
      );
    }
    return res.json({
      duty: r.rows[0],
      message: "ड्यूटी का स्टेटस DUTY BOOKED कर दिया गया।",
    });
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
      `SELECT id,role_posted_as,pickup_city,pickup_address_private,drop_city,drop_address_private,vehicle_type,duty_date,duty_time,payout_paise,notes_private,distance_km,distance_label,created_at,status,
      (user_id=$1) AS is_owner
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
        .json({ error: "सदस्यता अवधि 1, 3 या 6 महीने चुनें" });
    if (!razorpay || !selected.planId)
      return res
        .status(503)
        .json({
          error:
            "चुना हुआ सदस्यता प्लान अभी भुगतान सर्वर पर कॉन्फ़िगर नहीं है। अभी कोई पैसा नहीं कटा।",
        });
    const existing = await pool.query(
      `SELECT provider_subscription_id,status FROM subscriptions WHERE user_id=$1
      AND plan_months=$2 AND status IN ('created','authenticated','active','pending') ORDER BY created_at DESC LIMIT 1`,
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
      plan: "Gudiya Taxi Partner सदस्यता",
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
          String(doc.filename || "document").replace(/[\r\n"\\]/g, "_") + '"' ); res.set("Cache-Control", "no-store"); res.send(bytes); } catch (e) { next(e); } } ); app.post( "/api/admin/documents/:id/review", requireAdmin, async (req, res, next) => { try { const status = String(req.body.status || ""); if (!["approved", "rejected"].includes(status)) return res .status(400) .json({ error: "status must be approved or rejected" }); const client = await pool.connect(); try { await client.query("BEGIN"); const doc = await client.query( `UPDATE driver_documents SET status=$1,reviewer_note=$2,reviewed_at=now() WHERE id=$3 AND status='pending' RETURNING user_id`, [status, String(req.body.note || "").slice(0, 500), req.params.id] ); if (!doc.rowCount) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Pending document not found" }); } const docType = await client.query( "SELECT document_type FROM driver_documents WHERE id=$1", [req.params.id] ); const category = docType.rows[0]?.document_type?.startsWith("vendor_") ? "vendor" : "driver"; const types = category === "vendor" ? ["vendor_aadhaar"] : ["aadhaar", "driving_licence", "vehicle_rc"]; const pending = await client.query( `SELECT count(*)::int AS n FROM driver_documents WHERE user_id=$1 AND document_type = ANY($2::text[]) AND status='pending'`, [doc.rows[0].user_id, types] ); const rejected = await client.query( `SELECT count(*)::int AS n FROM driver_documents WHERE user_id=$1 AND document_type = ANY($2::text[]) AND status='rejected'`, [doc.rows[0].user_id, types] ); const approved = await client.query( `SELECT count(*)::int AS n FROM driver_documents WHERE user_id=$1 AND document_type = ANY($2::text[]) AND status='approved'`, [doc.rows[0].user_id, types] ); let verify = "pending"; if (Number(rejected.rows[0].n) > 0) verify = "rejected"; else if ( Number(pending.rows[0].n) === 0 && Number(approved.rows[0].n) >= (category === "vendor" ? 1 : 3) ) verify = "approved"; const column = category === "vendor" ? "vendor_verification" : "driver_verification"; await client.query( `UPDATE users SET ${column}=$1,updated_at=now() WHERE id=$2`, [verify, doc.rows[0].user_id] ); await client.query( "INSERT INTO audit_log(action,subject_type,subject_id,details) VALUES($1,$2,$3,$4)", [ category + "_document_review", "driver_document", String(req.params.id), JSON.stringify({ status, verify }), ] ); await client.query("COMMIT"); void sendPushToUserIds( [doc.rows[0].user_id], status === "approved" ? "दस्तावेज़ स्वीकृत हुए" : "दस्तावेज़ में सुधार आवश्यक", status === "approved" ? "आपके दस्तावेज़ स्वीकृत कर दिए गए हैं।" : "आपके दस्तावेज़ अस्वीकृत हुए हैं। कृपया ऐप में स्थिति देखें।", { type: "document_status", status, category } ); res.json({ ok: true, category, verification: verify }); } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); } } catch (e) { next(e); } } ); app.use((err, _req, res, _next) => { console.error(err.message); const status = Number(err.status) || 500; res .status(status) .json({ error: status < 500 ? err.message : "Server error" }); }); // Bootstrap the complete schema before accepting requests. This also fixes login's
// generic Server error on a fresh Gudiya database where users/device_sessions did not exist.
const schemaSql = fs.readFileSync(
  path.join(__dirname, "..", "schema.sql"),
  "utf8"
);
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
