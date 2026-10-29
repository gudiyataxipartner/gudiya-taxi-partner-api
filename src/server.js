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
const bcrypt = require("bcryptjs");
const firebaseAdmin = require("firebase-admin");

const app = express();
// Render terminates public traffic at its reverse proxy; trust the nearest proxy hop.
app.set("trust proxy", 1);
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

// Admin username/password login. Configure ADMIN_USERNAME, ADMIN_PASSWORD and JWT_SECRET
// as private environment variables on Render; never hard-code credentials in source code.
const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many login attempts. Please try again in 15 minutes.",
  },
});

app.post("/api/admin/auth/login", adminLoginLimiter, async (req, res) => {
  try {
    const configuredUsername = process.env.ADMIN_USERNAME || "";
    const configuredPassword = process.env.ADMIN_PASSWORD || "";
    const jwtSecret = process.env.JWT_SECRET || "";
    const username = String(req.body?.username || "");
    const password = String(req.body?.password || "");

    const safeEqual = (a, b) => {
      const aa = Buffer.from(String(a));
      const bb = Buffer.from(String(b));
      return (
        aa.length === bb.length &&
        aa.length > 0 &&
        crypto.timingSafeEqual(aa, bb)
      );
    };

    if (
      configuredUsername.length < 3 ||
      configuredPassword.length < 12 ||
      jwtSecret.length < 32
    ) {
      return res
        .status(503)
        .json({ error: "Admin login is not configured on the server." });
    }
    if (
      !safeEqual(username, configuredUsername) ||
      !safeEqual(password, configuredPassword)
    ) {
      return res.status(401).json({ error: "Username या Password गलत है।" });
    }

    const token = jwt.sign(
      { admin: true, purpose: "admin-session", username: configuredUsername },
      jwtSecret,
      { expiresIn: "12h", issuer: "gudiya-taxi-partner-admin" }
    );
    return res.json({ token, expiresIn: 43200, username: configuredUsername });
  } catch (error) {
    console.error("Admin login failed:", error.message);
    return res
      .status(500)
      .json({ error: "Admin login failed. Please try again." });
  }
});

function requireAdmin(req, res, next) {
  const authorization = req.get("authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (match) {
    try {
      const decoded = jwt.verify(match[1], process.env.JWT_SECRET || "", {
        issuer: "gudiya-taxi-partner-admin",
      });
      if (
        decoded?.admin === true &&
        decoded?.purpose === "admin-session" &&
        decoded?.username
      ) {
        req.admin = { username: decoded.username };
        return next();
      }
    } catch (_) {
      // Continue to legacy API-key validation for backward compatibility.
    }
  }

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
async function hasActiveMembership(userId) {
  // An explicit admin decision takes precedence over payment-based membership.
  const override = await pool.query(
    `SELECT status FROM admin_membership_overrides WHERE user_id=$1`,
    [userId]
  );
  if (override.rowCount) return override.rows[0].status === "paid";
  // Otherwise, only manually verified UPI subscriptions count. Legacy Razorpay rows are not
  // automatically trusted after switching providers.
  const r = await pool.query(
    `SELECT 1 FROM subscriptions
     WHERE user_id=$1 AND provider='manual_upi' AND status='active'
       AND provider_payment_id IS NOT NULL AND current_period_end > now()
     ORDER BY current_period_end DESC LIMIT 1`,
    [userId]
  );
  return !!r.rowCount;
}

function privateDuty(d) {
  return {
    id: d.id,
    pickupCity: d.pickup_city,
    dropCity: d.drop_city,
    vehicleType: d.vehicle_type,
    tripType: d.trip_type || "one_way",
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
          return res.status(409).json({
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
      return res.status(403).json({
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
      return res.status(400).json({
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
      return res.status(400).json({
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
      return res.status(201).json({
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
    const tripType = String(req.body.tripType || "one_way");
    if (!["one_way", "round_trip", "local_booking"].includes(tripType))
      return res.status(400).json({ error: "ड्यूटी का प्रकार सही नहीं है" });
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
      vehicle_type,trip_type,duty_date,duty_time,payout_paise,notes_private,distance_km,distance_label)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULL,'लगभग दूरी')
      RETURNING id,pickup_city,drop_city,vehicle_type,trip_type,duty_date,duty_time,distance_km,distance_label,created_at,status`,
      [
        req.auth.user_id,
        role,
        pickup,
        String(req.body.pickupAddress || "").slice(0, 500),
        drop,
        String(req.body.dropAddress || "").slice(0, 500),
        vehicle,
        tripType,
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
      `SELECT d.id,d.user_id,d.role_posted_as,d.pickup_city,d.pickup_address_private,d.drop_city,d.drop_address_private,d.vehicle_type,d.trip_type,
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
// Only the owner can update their own duty. Once it is accepted, changes require cancelling/reposting.
app.put("/api/duties/:id", requireAuth, async (req, res, next) => {
  try {
    const id = String(req.params.id || "");
    if (!/^\d+$/.test(id)) return res.status(400).json({ error: "ड्यूटी ID सही नहीं है" });
    const pickup = String(req.body.pickupCity || "").trim().slice(0, 120);
    const drop = String(req.body.dropCity || "").trim().slice(0, 120);
    const role = String(req.body.rolePostedAs || "driver");
    const vehicle = String(req.body.vehicleType || "").trim().slice(0, 80);
    const tripType = String(req.body.tripType || "one_way");
    if (!pickup || !drop || !vehicle) return res.status(400).json({ error: "Pickup, drop और vehicle जरूरी हैं" });
    if (!["driver", "vendor"].includes(role)) return res.status(400).json({ error: "Invalid role" });
    if (!["one_way", "round_trip", "local_booking"].includes(tripType)) return res.status(400).json({ error: "ड्यूटी का प्रकार सही नहीं है" });
    if (req.auth.role_mode !== "both" && req.auth.role_mode !== role) return res.status(403).json({ error: "इस भूमिका की अनुमति नहीं है" });
    const payout = req.body.payoutRupees == null || req.body.payoutRupees === "" ? null : Math.round(Number(req.body.payoutRupees) * 100);
    if (payout != null && (!Number.isFinite(payout) || payout < 0 || payout > 100000000)) return res.status(400).json({ error: "Invalid payout" });
    const r = await pool.query(`UPDATE duties SET role_posted_as=$1,pickup_city=$2,pickup_address_private=$3,drop_city=$4,drop_address_private=$5,vehicle_type=$6,trip_type=$7,duty_date=$8,duty_time=$9,payout_paise=$10,notes_private=$11
      WHERE id=$12 AND user_id=$13 AND status='open'
      RETURNING id,pickup_city,drop_city,vehicle_type,trip_type,duty_date,duty_time,payout_paise,notes_private,created_at,status`,
      [role,pickup,String(req.body.pickupAddress||"").slice(0,500),drop,String(req.body.dropAddress||"").slice(0,500),vehicle,tripType,req.body.dutyDate||null,req.body.dutyTime||null,payout,String(req.body.notes||"").slice(0,1000),id,req.auth.user_id]);
    if (!r.rowCount) {
      const existing = await pool.query("SELECT user_id,status FROM duties WHERE id=$1", [id]);
      if (!existing.rowCount) return res.status(404).json({ error: "ड्यूटी नहीं मिली" });
      if (String(existing.rows[0].user_id) !== String(req.auth.user_id)) return res.status(403).json({ error: "केवल ड्यूटी पोस्ट करने वाला इसे अपडेट कर सकता है" });
      return res.status(409).json({ error: "यह ड्यूटी अब अपडेट नहीं हो सकती। स्वीकार होने के बाद बदलाव बंद हैं।" });
    }
    broadcastDutyUpdate();
    return res.json({ duty: r.rows[0], message: "ड्यूटी अपडेट हो गई।" });
  } catch (e) { next(e); }
});
app.post("/api/duties/:id/cancel", requireAuth, async (req, res, next) => {
  try {
    const id = String(req.params.id || "");
    if (!/^\d+$/.test(id)) return res.status(400).json({ error: "ड्यूटी ID सही नहीं है" });
    const r = await pool.query(`UPDATE duties SET status='cancelled' WHERE id=$1 AND user_id=$2 AND status IN ('open','accepted')
      RETURNING id,pickup_city,drop_city,status,accepted_by_user_id`, [id,req.auth.user_id]);
    if (!r.rowCount) {
      const existing = await pool.query("SELECT user_id,status FROM duties WHERE id=$1", [id]);
      if (!existing.rowCount) return res.status(404).json({ error: "ड्यूटी नहीं मिली" });
      if (String(existing.rows[0].user_id) !== String(req.auth.user_id)) return res.status(403).json({ error: "केवल ड्यूटी पोस्ट करने वाला इसे कैंसल कर सकता है" });
      return res.status(409).json({ error: "यह ड्यूटी पहले ही बुक, पूरी या कैंसल हो चुकी है" });
    }
    broadcastDutyUpdate();
    if (r.rows[0].accepted_by_user_id) void sendPushToUserIds([r.rows[0].accepted_by_user_id], "ड्यूटी कैंसल हुई", `${r.rows[0].pickup_city} से ${r.rows[0].drop_city} की ड्यूटी पोस्ट करने वाले ने कैंसल कर दी है।`, { type: "duty_cancelled", dutyId: r.rows[0].id });
    return res.json({ duty: r.rows[0], message: "ड्यूटी कैंसल हो गई।" });
  } catch (e) { next(e); }
});
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
        return res.status(409).json({
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
      d.vehicle_type,d.trip_type,d.duty_date,d.duty_time,d.payout_paise,d.notes_private,d.distance_km,d.distance_label,d.created_at,d.status,
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
      `SELECT id,role_posted_as,pickup_city,pickup_address_private,drop_city,drop_address_private,vehicle_type,trip_type,duty_date,duty_time,payout_paise,notes_private,distance_km,distance_label,created_at,status,
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

// Direct UPI payments: a submitted UTR stays pending until an admin verifies the money in the bank.
const UPI_PLANS = { 1: 51, 3: 151, 6: 301 };
app.post(
  "/api/membership/payments",
  requireAuth,
  rateLimit({ windowMs: 60 * 60_000, limit: 8 }),
  async (req, res, next) => {
    try {
      const months = Number(req.body.months);
      const amount = UPI_PLANS[months];
      const utr = String(req.body.utr || "")
        .trim()
        .replace(/\s+/g, "");
      if (!amount)
        return res.status(400).json({ error: "सही सदस्यता प्लान चुनें।" });
      if (!/^[A-Za-z0-9-]{8,40}$/.test(utr))
        return res
          .status(400)
          .json({ error: "UPI Transaction ID / UTR सही नहीं है।" });
      const pending = await pool.query(
        "SELECT id FROM membership_payment_requests WHERE user_id=$1 AND status='pending' ORDER BY created_at DESC LIMIT 1",
        [req.auth.user_id]
      );
      if (pending.rowCount)
        return res.status(409).json({
          error:
            "आपका एक भुगतान पहले से जाँच के लिए Pending है। Admin के निर्णय का इंतज़ार करें।",
        });
      const created = await pool.query(
        `INSERT INTO membership_payment_requests(user_id,plan_months,amount_rupees,utr)
       VALUES($1,$2,$3,$4) RETURNING id,plan_months,amount_rupees,status,created_at`,
        [req.auth.user_id, months, amount, utr]
      );
      return res.status(201).json({
        ok: true,
        paymentRequest: created.rows[0],
        message:
          "भुगतान संदर्भ जाँच के लिए जमा हो गया है। बैंक में रकम की पुष्टि के बाद ही सदस्यता सक्रिय होगी।",
      });
    } catch (e) {
      if (e.code === "23505")
        return res.status(409).json({
          error:
            "यह UTR पहले जमा हो चुका है। अपने UPI ऐप से सही Transaction ID जाँचें।",
        });
      next(e);
    }
  }
);

// UPI AutoPay is disabled. No gateway/recurring charge is initiated by this endpoint.
app.post("/api/membership/autopay", requireAuth, async (_req, res) => {
  return res.status(410).json({
    error:
      "UPI AutoPay बंद है। कृपया सामान्य UPI भुगतान करें और Transaction ID जमा करें।",
    paymentAvailable: true,
  });
});

app.get("/api/membership", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query(
      `SELECT status,current_period_end,created_at,plan_months,amount_rupees,provider
       FROM subscriptions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1`,
      [req.auth.user_id]
    );
    const payment = await pool.query(
      `SELECT id,status,plan_months,amount_rupees,created_at,admin_note
       FROM membership_payment_requests WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1`,
      [req.auth.user_id]
    );
    let subscription = r.rows[0] || null;
    const overrideResult = await pool.query(
      `SELECT status, note, updated_at FROM admin_membership_overrides WHERE user_id=$1`,
      [req.auth.user_id]
    );
    const adminOverride = overrideResult.rows[0] || null;
    const active = await hasActiveMembership(req.auth.user_id);
    if (adminOverride?.status === "paid") {
      subscription = {
        status: "active",
        provider: "admin_override",
        plan_months: null,
        amount_rupees: 0,
        current_period_end: null,
        admin_note: adminOverride.note,
      };
    } else if (adminOverride?.status === "unpaid") {
      subscription = {
        status: "payment_required",
        provider: "admin_override",
        plan_months: null,
        amount_rupees: 0,
        current_period_end: null,
        admin_note: adminOverride.note,
      };
    } else if (
      subscription &&
      subscription.provider !== "manual_upi" &&
      subscription.status === "active"
    ) {
      subscription = { ...subscription, status: "payment_required" };
    } else if (
      subscription?.provider === "manual_upi" &&
      subscription.status === "active" &&
      new Date(subscription.current_period_end).getTime() <= Date.now()
    ) {
      subscription = { ...subscription, status: "expired" };
    }
    return res.json({
      plan: "Gudiya Taxi Partner सदस्यता",
      plans: [
        { months: 1, amountRupees: 51 },
        { months: 3, amountRupees: 151 },
        { months: 6, amountRupees: 301 },
      ],
      autopayOnly: false,
      paymentAvailable: true,
      paymentMethod: "direct_upi_manual_verification",
      active,
      adminOverride: adminOverride
        ? {
            status: adminOverride.status,
            note: adminOverride.note,
            updatedAt: adminOverride.updated_at,
          }
        : null,
      subscription,
      paymentRequest: payment.rows[0] || null,
    });
  } catch (e) {
    next(e);
  }
});

// Admin review page: approve only after checking the actual bank/UPI receipt.
app.get("/admin-membership", (_req, res) => {
  res.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
  );
  res.type("html")
    .send(`<!doctype html><html lang="hi"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Gudiya Taxi Partner — UPI Review</title><body style="font:16px Arial,sans-serif;max-width:760px;margin:24px auto;padding:0 14px;background:#f4f8fa;color:#123"><h2>Gudiya Taxi Partner — Admin Membership</h2><p>Admin API Key किसी को साझा न करें। बैंक/UPI में रकम की पुष्टि किए बिना UPI अनुरोध Approve न करें।</p><label>Admin API Key <input id="key" type="password" autocomplete="off" style="width:100%;padding:12px;margin:8px 0 12px;box-sizing:border-box"></label><section style="background:#fff;border:1px solid #ccdce4;border-radius:12px;padding:14px;margin:16px 0"><h3>किसी User को Paid / Unpaid करें</h3><p>User का registered mobile number डालें। यह Admin override payment के बिना भी membership चालू/बंद करेगा।</p><input id="userphone" inputmode="numeric" maxlength="10" placeholder="Registered 10-digit mobile number" style="width:100%;padding:12px;box-sizing:border-box"><input id="overridenote" placeholder="कारण / नोट (वैकल्पिक)" style="width:100%;padding:12px;margin:8px 0;box-sizing:border-box"><button onclick="findMembershipUser()" style="padding:10px 14px">User खोजें</button><div id="userresult" style="margin-top:12px"></div></section><hr><h3>UPI भुगतान अनुरोध</h3><button onclick="loadPayments()" style="padding:12px 18px">Pending भुगतान देखें</button><div id="msg" style="margin:14px 0"></div><div id="list"></div><script>
async function call(path,options={}){const key=document.getElementById('key').value.trim();if(!key)throw Error('Admin API Key भरें');const r=await fetch(path,{...options,headers:{'Content-Type':'application/json','x-admin-key':key,...(options.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||'Request failed');return d}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))} async function findMembershipUser(){const box=document.getElementById('userresult');box.textContent='User खोजा जा रहा है…';try{const phone=document.getElementById('userphone').value.trim();const d=await call('/api/admin/membership/user?phone='+encodeURIComponent(phone));const u=d.user;box.innerHTML='<b>'+esc(u.name||'User')+'</b> · '+esc(u.phone)+'<p>अभी की स्थिति: <b>'+esc(u.membershipStatus)+'</b></p><button onclick="setMembership('+Number(u.id)+',&quot;paid&quot;)" style="padding:10px;background:#087b62;color:white;border:0;border-radius:8px;margin-right:8px">बिना Payment Paid करें</button><button onclick="setMembership(+Number(u.id)+',&quot;unpaid&quot;)" style="padding:10px;background:#9d2c2c;color:white;border:0;border-radius:8px">Paid से हटाएँ (Unpaid)</button>';}catch(e){box.textContent='त्रुटि: '+e.message}} async function setMembership(id,status){const word=status==='paid'?'Paid':'Unpaid';if(!confirm('क्या इस User को '+word+' करना है?'))return;try{const note=document.getElementById('overridenote').value.trim();const d=await call('/api/admin/users/'+id+'/membership-override',{method:'POST',body:JSON.stringify({status,note})});document.getElementById('userresult').textContent=d.message||'स्थिति अपडेट हो गई';}catch(e){document.getElementById('userresult').textContent='त्रुटि: '+e.message}} async function loadPayments(){const msg=document.getElementById('msg'),list=document.getElementById('list');msg.textContent='लोड हो रहा है…';try{const d=await call('/api/admin/membership/payments/pending');list.innerHTML=(d.payments||[]).map(p=>'<div style="background:white;border:1px solid #ccdce4;border-radius:12px;padding:14px;margin:12px 0"><b>'+esc(p.user_name||'User')+'</b> · '+esc(p.phone)+'<p>प्लान: '+esc(p.plan_months)+' महीने · ₹'+esc(p.amount_rupees)+'</p><p>UTR: <b>'+esc(p.utr)+'</b></p><p>Request ID: '+Number(p.id)+' · '+esc(p.created_at)+'</p><input id="note-'+Number(p.id)+'" placeholder="नोट (वैकल्पिक)" style="width:100%;padding:9px;box-sizing:border-box"><div style="display:flex;gap:8px;margin-top:10px"><button onclick="review('+Number(p.id)+',\'approved\')" style="padding:10px;background:#087b62;color:white;border:0;border-radius:8px">भुगतान मिला — Approve</button><button onclick="review('+Number(p.id)+',\'rejected\')" style="padding:10px;background:#9d2c2c;color:white;border:0;border-radius:8px">Reject</button></div></div>').join('')||'<p>अभी कोई Pending भुगतान नहीं है।</p>';msg.textContent='Pending भुगतान: '+(d.payments||[]).length;}catch(e){msg.textContent='त्रुटि: '+e.message}}
async function review(id,status){if(status==='approved'&&!confirm('क्या आपने बैंक में रकम और UTR की पुष्टि कर ली है? पुष्टि के बाद सदस्यता सक्रिय होगी।'))return;const note=document.getElementById('note-'+id)?.value||'';try{const d=await call('/api/admin/membership/payments/'+id+'/review',{method:'POST',body:JSON.stringify({status,note})});document.getElementById('msg').textContent=d.message||'Updated';await loadPayments()}catch(e){document.getElementById('msg').textContent='त्रुटि: '+e.message}}
</script></body></html>`);
});

// Admin can explicitly override a user's paid category without collecting payment.
app.get("/api/admin/membership/user", requireAdmin, async (req, res, next) => {
  try {
    const phone = String(req.query.phone || "").trim();
    if (!/^\d{10}$/.test(phone))
      return res
        .status(400)
        .json({ error: "10 अंकों का registered mobile number डालें" });
    const found = await pool.query(
      `SELECT id,name,phone FROM users WHERE phone=$1 LIMIT 1`,
      [phone]
    );
    if (!found.rowCount)
      return res
        .status(404)
        .json({ error: "इस mobile number से User नहीं मिला" });
    const u = found.rows[0];
    const override = await pool.query(
      `SELECT status FROM admin_membership_overrides WHERE user_id=$1`,
      [u.id]
    );
    const paid = await hasActiveMembership(u.id);
    return res.json({
      user: {
        ...u,
        membershipStatus: override.rowCount
          ? override.rows[0].status === "paid"
            ? "Admin द्वारा Paid"
            : "Admin द्वारा Unpaid"
          : paid
          ? "Paid"
          : "Unpaid",
      },
    });
  } catch (e) {
    next(e);
  }
});

app.post(
  "/api/admin/users/:id/membership-override",
  requireAdmin,
  async (req, res, next) => {
    try {
      const userId = String(req.params.id || "");
      const status = String(req.body.status || "");
      const note = String(req.body.note || "").slice(0, 500);
      if (!/^\d+$/.test(userId) || !["paid", "unpaid"].includes(status))
        return res.status(400).json({ error: "User ID या status सही नहीं है" });
      const user = await pool.query(`SELECT id FROM users WHERE id=$1`, [
        userId,
      ]);
      if (!user.rowCount)
        return res.status(404).json({ error: "User नहीं मिला" });
      await pool.query(
        `INSERT INTO admin_membership_overrides(user_id,status,note,updated_at)
       VALUES($1,$2,$3,now())
       ON CONFLICT(user_id) DO UPDATE SET status=EXCLUDED.status,note=EXCLUDED.note,updated_at=now()`,
        [userId, status, note]
      );
      await pool.query(
        `INSERT INTO audit_log(action,subject_type,subject_id,details) VALUES($1,'user',$2,$3)`,
        [
          "admin_membership_override_" + status,
          String(userId),
          JSON.stringify({ status, note }),
        ]
      );
      void sendPushToUserIds(
        [userId],
        status === "paid" ? "Membership सक्रिय" : "Membership स्थिति बदली",
        status === "paid"
          ? "Admin ने आपकी membership Paid कर दी है।"
          : "Admin ने आपकी membership Unpaid कर दी है।",
        { type: "membership_status", status }
      );
      return res.json({
        ok: true,
        status,
        message:
          status === "paid"
            ? "User को बिना payment Paid कर दिया गया।"
            : "User को Paid category से हटाकर Unpaid कर दिया गया।",
      });
    } catch (e) {
      next(e);
    }
  }
);

app.get(
  "/api/admin/membership/payments/pending",
  requireAdmin,
  async (_req, res, next) => {
    try {
      const r = await pool.query(
        `SELECT p.id,p.user_id,u.name AS user_name,u.phone,p.plan_months,p.amount_rupees,p.utr,p.status,p.created_at
       FROM membership_payment_requests p JOIN users u ON u.id=p.user_id
       WHERE p.status='pending' ORDER BY p.created_at ASC LIMIT 200`
      );
      res.json({ payments: r.rows });
    } catch (e) {
      next(e);
    }
  }
);

app.post(
  "/api/admin/membership/payments/:id/review",
  requireAdmin,
  async (req, res, next) => {
    const status = String(req.body.status || "");
    if (
      !/^[0-9]+$/.test(String(req.params.id)) ||
      !["approved", "rejected"].includes(status)
    )
      return res
        .status(400)
        .json({ error: "भुगतान अनुरोध या status सही नहीं है" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        `SELECT id,user_id,plan_months,amount_rupees,utr FROM membership_payment_requests WHERE id=$1 AND status='pending' FOR UPDATE`,
        [req.params.id]
      );
      if (!found.rowCount) {
        await client.query("ROLLBACK");
        return res
          .status(404)
          .json({ error: "Pending payment request नहीं मिला" });
      }
      const p = found.rows[0];
      if (status === "approved") {
        // Extends from the later of now or the user's existing verified manual-UPI expiry.
        await client.query(
          `INSERT INTO subscriptions(user_id,provider,provider_payment_id,plan_months,amount_rupees,status,current_period_end)
         VALUES($1,'manual_upi',$2,$3,$4,'active',
           GREATEST(now(), COALESCE((SELECT MAX(current_period_end) FROM subscriptions WHERE user_id=$1 AND provider='manual_upi' AND status='active'), now()))
             + ($3::text || ' months')::interval)`,
          [p.user_id, "UPI:" + p.utr, p.plan_months, p.amount_rupees]
        );
      }
      await client.query(
        `UPDATE membership_payment_requests SET status=$1,admin_note=$2,reviewed_at=now(),reviewed_by='admin_api' WHERE id=$3`,
        [status, String(req.body.note || "").slice(0, 500), p.id]
      );
      await client.query(
        `INSERT INTO audit_log(action,subject_type,subject_id,details) VALUES($1,'membership_payment_request',$2,$3)`,
        [
          "membership_payment_" + status,
          String(p.id),
          JSON.stringify({
            status,
            amountRupees: p.amount_rupees,
            planMonths: p.plan_months,
            utr: p.utr,
          }),
        ]
      );
      await client.query("COMMIT");
      return res.json({
        ok: true,
        status,
        message:
          status === "approved"
            ? "भुगतान स्वीकृत और सदस्यता सक्रिय कर दी गई।"
            : "भुगतान अनुरोध अस्वीकार कर दिया गया।",
      });
    } catch (e) {
      await client.query("ROLLBACK").catch(() => {});
      next(e);
    } finally {
      client.release();
    }
  }
);

/* GUDIYA TAXI PARTNER ADMIN API ROUTES */

app.get("/api/admin/dashboard", requireAdmin, async (_req, res, next) => {
  try {
    const [users, active, documents, duties, payments, paid] =
      await Promise.all([
        pool.query(`SELECT COUNT(*)::int AS total FROM users`),
        pool.query(`
          SELECT COUNT(DISTINCT user_id)::int AS total
          FROM device_sessions
          WHERE revoked_at IS NULL
            AND last_seen_at > now() - interval '30 days'
        `),
        pool.query(`
          SELECT COUNT(*)::int AS total
          FROM driver_documents WHERE status='pending'
        `),
        pool.query(`
          SELECT COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE status='open')::int AS open,
            COUNT(*) FILTER (WHERE status='accepted')::int AS accepted,
            COUNT(*) FILTER (WHERE status='booked')::int AS booked,
            COUNT(*) FILTER (WHERE status='completed')::int AS completed,
            COUNT(*) FILTER (WHERE status='cancelled')::int AS cancelled
          FROM duties
        `),
        pool.query(`
          SELECT COUNT(*)::int AS total
          FROM membership_payment_requests WHERE status='pending'
        `),
        pool.query(`
          SELECT COUNT(*)::int AS total
          FROM users u
          LEFT JOIN admin_membership_overrides o ON o.user_id=u.id
          WHERE COALESCE(
            o.status,
            CASE WHEN EXISTS (
              SELECT 1 FROM subscriptions s
              WHERE s.user_id=u.id
                AND s.provider='manual_upi'
                AND s.status='active'
                AND s.provider_payment_id IS NOT NULL
                AND s.current_period_end > now()
            ) THEN 'paid' ELSE 'unpaid' END
          )='paid'
        `),
      ]);

    const totalUsers = Number(users.rows[0].total || 0);

    res.json({
      users: {
        total: totalUsers,
        paid: Number(paid.rows[0].total || 0),
        unpaid: Math.max(0, totalUsers - Number(paid.rows[0].total || 0)),
        active: Number(active.rows[0].total || 0),
      },
      documents: {
        pending: Number(documents.rows[0].total || 0),
      },
      duties: duties.rows[0],
      payments: {
        pending: Number(payments.rows[0].total || 0),
      },
    });
  } catch (e) {
    next(e);
  }
});

app.get("/api/admin/users", requireAdmin, async (req, res, next) => {
  try {
    const q = String(req.query.q || "")
      .trim()
      .slice(0, 100);

    const result = await pool.query(
      `
      SELECT u.id, u.name, u.phone, u.role_mode,
        u.driver_verification, u.vendor_verification, u.created_at,
        o.status AS admin_override_status,
        CASE
          WHEN o.status IS NOT NULL THEN o.status
          WHEN EXISTS (
            SELECT 1 FROM subscriptions s
            WHERE s.user_id=u.id
              AND s.provider='manual_upi'
              AND s.status='active'
              AND s.provider_payment_id IS NOT NULL
              AND s.current_period_end > now()
          ) THEN 'paid'
          ELSE 'unpaid'
        END AS membership_status,
        CASE WHEN EXISTS (
          SELECT 1 FROM device_sessions ds
          WHERE ds.user_id=u.id
            AND ds.revoked_at IS NULL
            AND ds.last_seen_at > now() - interval '30 days'
        ) THEN 'active' ELSE 'inactive' END AS login_status
      FROM users u
      LEFT JOIN admin_membership_overrides o ON o.user_id=u.id
      WHERE ($1='' OR u.name ILIKE '%' || $1 || '%'
        OR u.phone ILIKE '%' || $1 || '%'
        OR u.id::text=$1)
      ORDER BY u.created_at DESC
      LIMIT 500
    `,
      [q]
    );

    res.json({ users: result.rows });
  } catch (e) {
    next(e);
  }
});

// Admin-only password reset. Keep this consistent with /api/auth/password/login:
// passwords are stored as bcrypt hashes and old device sessions are revoked.
app.post(
  "/api/admin/users/:id/reset-password",
  requireAdmin,
  async (req, res, next) => {
    try {
      const id = String(req.params.id || "").trim();
      const temporaryPassword =
        typeof req.body?.temporaryPassword === "string"
          ? req.body.temporaryPassword
          : "";

      if (!/^\d+$/.test(id) || Number(id) < 1) {
        return res.status(400).json({ error: "Invalid user ID" });
      }
      if (
        temporaryPassword.length < 8 ||
        temporaryPassword.length > 72 ||
        Buffer.byteLength(temporaryPassword, "utf8") > 72
      ) {
        return res.status(400).json({
          error: "Temporary password must be 8–72 characters and no more than 72 UTF-8 bytes",
        });
      }

      // Match the registration/login implementation: bcrypt with cost factor 12.
      const passwordHash = await bcrypt.hash(temporaryPassword, 12);
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const found = await client.query(
          "SELECT id, phone FROM users WHERE id=$1 FOR UPDATE",
          [id]
        );
        if (!found.rowCount) {
          await client.query("ROLLBACK");
          return res.status(404).json({ error: "User not found" });
        }

        await client.query(
          "UPDATE users SET password_hash=$1, updated_at=now() WHERE id=$2",
          [passwordHash, id]
        );
        await client.query(
          "UPDATE device_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL",
          [id]
        );
        await client.query("DELETE FROM push_tokens WHERE user_id=$1", [id]);
        await client.query(
          "INSERT INTO audit_log(action,subject_type,subject_id,details) VALUES($1,$2,$3,$4)",
          [
            "admin_password_reset",
            "user",
            String(id),
            JSON.stringify({
              phone: found.rows[0].phone,
              admin: req.admin?.username || "admin-api-key",
            }),
          ]
        );
        await client.query("COMMIT");
        res.set("Cache-Control", "no-store");
        return res.json({
          ok: true,
          message: "Password reset successfully. Please log in with the temporary password.",
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
  }
);

app.delete("/api/admin/users/:id", requireAdmin, async (req, res, next) => {
  const id = String(req.params.id || "").trim();

  if (!/^\d+$/.test(id) || Number(id) < 1) {
    return res.status(400).json({ error: "Invalid user ID" });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const found = await client.query(
      "SELECT id, name, phone FROM users WHERE id=$1 FOR UPDATE",
      [id]
    );

    if (!found.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found" });
    }

    const user = found.rows[0];

    await client.query(
      "INSERT INTO audit_log(action,subject_type,subject_id,details) VALUES($1,$2,$3,$4)",
      [
        "admin_user_deleted",
        "user",
        String(user.id),
        JSON.stringify({
          name: user.name,
          phone: user.phone,
          admin: req.admin?.username || "admin-api-key"
        })
      ]
    );

    await client.query("DELETE FROM users WHERE id=$1", [id]);
    await client.query("COMMIT");

    res.set("Cache-Control", "no-store");
    return res.json({ ok: true, deletedUser: user });
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {}

    if (e.code === "23503") {
      return res.status(409).json({
        error: "User-related data has a foreign-key dependency that is not configured for cascade deletion."
      });
    }

    next(e);
  } finally {
    client.release();
  }
});

app.get("/api/admin/users/:id", requireAdmin, async (req, res, next) => {
  try {
    if (!/^\d+$/.test(String(req.params.id))) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    const found = await pool.query(
      `
      SELECT u.id, u.name, u.phone, u.role_mode,
        u.driver_verification, u.vendor_verification, u.created_at,
        COALESCE(o.status, CASE WHEN EXISTS (
          SELECT 1 FROM subscriptions s
          WHERE s.user_id=u.id
            AND s.provider='manual_upi'
            AND s.status='active'
            AND s.provider_payment_id IS NOT NULL
            AND s.current_period_end > now()
        ) THEN 'paid' ELSE 'unpaid' END) AS membership_status
      FROM users u
      LEFT JOIN admin_membership_overrides o ON o.user_id=u.id
      WHERE u.id=$1
    `,
      [req.params.id]
    );

    if (!found.rowCount) {
      return res.status(404).json({ error: "User not found" });
    }

    const [docs, duties, sessions] = await Promise.all([
      pool.query(
        `
        SELECT id, document_type, status, created_at, reviewed_at
        FROM driver_documents
        WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50
      `,
        [req.params.id]
      ),
      pool.query(
        `
        SELECT id, pickup_city, drop_city, vehicle_type,
          duty_date, duty_time, status, created_at
        FROM duties
        WHERE user_id=$1 OR accepted_by_user_id=$1
        ORDER BY created_at DESC LIMIT 50
      `,
        [req.params.id]
      ),
      pool.query(
        `
        SELECT created_at, last_seen_at, revoked_at
        FROM device_sessions
        WHERE user_id=$1 ORDER BY last_seen_at DESC LIMIT 20
      `,
        [req.params.id]
      ),
    ]);

    res.json({
      user: found.rows[0],
      documents: docs.rows,
      duties: duties.rows,
      sessions: sessions.rows,
    });
  } catch (e) {
    next(e);
  }
});

app.get("/api/admin/documents", requireAdmin, async (req, res, next) => {
  try {
    const status = String(req.query.status || "all");
    const type = String(req.query.type || "all");

    const result = await pool.query(
      `
      SELECT d.id, d.user_id, d.document_type, d.status,
        d.created_at, d.reviewed_at,
        u.name AS user_name, u.phone, u.role_mode
      FROM driver_documents d
      JOIN users u ON u.id=d.user_id
      WHERE ($1='all' OR d.status=$1)
        AND ($2='all' OR d.document_type=$2)
      ORDER BY d.created_at DESC
      LIMIT 500
    `,
      [status, type]
    );

    res.json({ documents: result.rows });
  } catch (e) {
    next(e);
  }
});

app.get("/api/admin/duties", requireAdmin, async (req, res, next) => {
  try {
    const q = String(req.query.q || "")
      .trim()
      .slice(0, 100);
    const status = String(req.query.status || "all");
    const role = String(req.query.role || "all");

    const result = await pool.query(
      `
      SELECT d.id, d.user_id, d.pickup_city, d.drop_city,
        d.vehicle_type, d.role_posted_as, d.duty_date, d.duty_time,
        d.distance_km, d.payout_paise, d.status, d.created_at,
        u.name AS poster_name, u.phone AS poster_phone,
        a.name AS accepted_by_name, a.phone AS accepted_by_phone
      FROM duties d
      JOIN users u ON u.id=d.user_id
      LEFT JOIN users a ON a.id=d.accepted_by_user_id
      WHERE ($1='' OR d.pickup_city ILIKE '%' || $1 || '%'
        OR d.drop_city ILIKE '%' || $1 || '%'
        OR u.phone ILIKE '%' || $1 || '%'
        OR u.name ILIKE '%' || $1 || '%'
        OR d.id::text=$1)
        AND ($2='all' OR d.status=$2)
        AND ($3='all' OR d.role_posted_as=$3)
      ORDER BY d.created_at DESC
      LIMIT 500
    `,
      [q, status, role]
    );

    res.json({ duties: result.rows });
  } catch (e) {
    next(e);
  }
});

/* END GUDIYA TAXI PARTNER ADMIN API ROUTES */

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
// Resolve schema.sql across the common Render layouts. The API entry point is
// src/server.js and schema.sql should normally be at the repository root.
const schemaCandidates = [
  path.join(__dirname, "schema.sql"),
  path.join(__dirname, "..", "schema.sql"),
  path.join(process.cwd(), "schema.sql"),
  path.join(process.cwd(), "src", "schema.sql"),
];
const schemaPath = schemaCandidates.find((candidate) =>
  fs.existsSync(candidate)
);
if (!schemaPath) {
  throw new Error(
    "schema.sql not found. Checked: " +
      schemaCandidates.join(", ") +
      ". Ensure schema.sql is committed to the deployed repository root."
  );
}
console.log("Loading database schema from:", schemaPath);
const schemaSql = fs.readFileSync(schemaPath, "utf8");
pool
  .query(schemaSql)
  .then(() => pool.query("ALTER TABLE duties ADD COLUMN IF NOT EXISTS trip_type TEXT NOT NULL DEFAULT 'one_way'"))
  .then(() => pool.query("ALTER TABLE duties DROP CONSTRAINT IF EXISTS duties_trip_type_check"))
  .then(() => pool.query("ALTER TABLE duties ADD CONSTRAINT duties_trip_type_check CHECK (trip_type IN ('one_way','round_trip','local_booking'))"))
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
    pool.query(`
    CREATE TABLE IF NOT EXISTS membership_payment_requests (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      plan_months INTEGER NOT NULL CHECK (plan_months IN (1,3,6)),
      amount_rupees INTEGER NOT NULL CHECK (amount_rupees IN (51,151,301)),
      utr VARCHAR(40) NOT NULL UNIQUE,
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
      admin_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      reviewed_at TIMESTAMPTZ,
      reviewed_by TEXT
    )
  `)
  )
  .then(() =>
    pool.query(`
    CREATE TABLE IF NOT EXISTS admin_membership_overrides (
      user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL CHECK (status IN ('paid','unpaid')),
      note TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `)
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
