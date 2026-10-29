CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  phone VARCHAR(10) UNIQUE NOT NULL,
  password_hash TEXT,
  name TEXT NOT NULL DEFAULT '',
  role_mode TEXT NOT NULL DEFAULT 'both' CHECK (role_mode IN ('driver','vendor','both')),
  driver_verification TEXT NOT NULL DEFAULT 'not_submitted'
    CHECK (driver_verification IN ('not_submitted','pending','approved','rejected')),
  vendor_verification TEXT NOT NULL DEFAULT 'not_submitted'
    CHECK (vendor_verification IN ('not_submitted','pending','approved','rejected')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS device_sessions (
  id UUID PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS device_sessions_user_active ON device_sessions(user_id) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS duties (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_posted_as TEXT NOT NULL CHECK (role_posted_as IN ('driver','vendor')),
  pickup_city TEXT NOT NULL,
  pickup_address_private TEXT,
  drop_city TEXT NOT NULL,
  drop_address_private TEXT,
  vehicle_type TEXT NOT NULL,
  trip_type TEXT NOT NULL DEFAULT 'one_way' CHECK (trip_type IN ('one_way','round_trip','local_booking')),
  duty_date DATE,
  duty_time TIME,
  payout_paise INTEGER,
  notes_private TEXT,
  distance_km NUMERIC(8,1),
  distance_label TEXT NOT NULL DEFAULT 'लगभग दूरी',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','accepted','completed','cancelled'))
);
CREATE INDEX IF NOT EXISTS duties_open_created ON duties(status, created_at DESC);
CREATE TABLE IF NOT EXISTS subscriptions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL DEFAULT 'none',
  provider_subscription_id TEXT UNIQUE,
  provider_payment_id TEXT,
  plan_months INTEGER CHECK (plan_months IN (1,3,6)),
  amount_rupees INTEGER CHECK (amount_rupees IN (51,151,301)),
  status TEXT NOT NULL DEFAULT 'created'
    CHECK (status IN ('created','authenticated','active','pending','halted','cancelled','expired','failed')),
  current_period_end TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS subscriptions_user_status ON subscriptions(user_id, status, current_period_end DESC);
CREATE TABLE IF NOT EXISTS webhook_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS driver_documents (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  document_type TEXT NOT NULL CHECK (document_type IN ('aadhaar','vendor_aadhaar','driving_licence','vehicle_rc','vendor_gst','vendor_pan')),
  secure_object_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  reviewer_note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_at TIMESTAMPTZ,
  UNIQUE (user_id, document_type)
);
CREATE INDEX IF NOT EXISTS driver_documents_pending ON driver_documents(status, created_at);
CREATE TABLE IF NOT EXISTS admin_membership_overrides (
  user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('paid','unpaid')),
  note TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  actor_user_id BIGINT,
  action TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Safe migration for an already-created production database
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_verification TEXT NOT NULL DEFAULT 'not_submitted';
ALTER TABLE driver_documents DROP CONSTRAINT IF EXISTS driver_documents_document_type_check;
ALTER TABLE driver_documents ADD CONSTRAINT driver_documents_document_type_check
  CHECK (document_type IN ('aadhaar','vendor_aadhaar','driving_licence','vehicle_rc','vendor_gst','vendor_pan'));


-- Duty acceptance: the first successful driver acceptance wins atomically.
ALTER TABLE duties ADD COLUMN IF NOT EXISTS accepted_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL;
-- Allow the duty owner to confirm a booking after a driver accepts the duty.
ALTER TABLE duties DROP CONSTRAINT IF EXISTS duties_status_check;
ALTER TABLE duties ADD CONSTRAINT duties_status_check CHECK (status IN ('open','accepted','booked','completed','cancelled'));

ALTER TABLE duties ADD COLUMN IF NOT EXISTS duty_time TIME;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS plan_months INTEGER;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS amount_rupees INTEGER;
CREATE INDEX IF NOT EXISTS duties_accepted_by_user ON duties(accepted_by_user_id) WHERE accepted_by_user_id IS NOT NULL;


-- Firebase Cloud Messaging device tokens. Tokens are tied to authenticated accounts.
CREATE TABLE IF NOT EXISTS push_tokens (
  token TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS push_tokens_user_id ON push_tokens(user_id);


-- Manual BharatPe UPI payment claims; a human admin must verify the UTR before activation.
CREATE TABLE IF NOT EXISTS membership_upi_payments (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL DEFAULT 'bharatpe_upi',
  upi_id TEXT NOT NULL DEFAULT 'BHARATPE2Q0G0U8Z8L34528@unitype',
  plan_months INTEGER NOT NULL CHECK (plan_months IN (1,3,6)),
  amount_rupees INTEGER NOT NULL CHECK (amount_rupees IN (51,151,301)),
  utr TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_at TIMESTAMPTZ,
  reviewer_note TEXT
);
CREATE INDEX IF NOT EXISTS membership_upi_payments_pending ON membership_upi_payments(status, created_at DESC);
