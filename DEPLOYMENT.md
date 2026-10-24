# Gudiya Taxi Partner backend setup checklist

1. Create a managed PostgreSQL database and apply `schema.sql`.
2. Deploy this Node.js service on a server with HTTPS.
3. Copy `.env.example` to `.env` in the hosting secret manager. Use unique random secrets.
4. Configure Twilio Verify for SMS OTP, and Razorpay subscription webhooks. Keep all secret keys server-side.
5. In Razorpay, create three recurring plans matching ₹51 for 1 month, ₹151 for 3 months, and ₹301 for 6 months. Set `RAZORPAY_MEMBERSHIP_PLAN_1M_ID`, `RAZORPAY_MEMBERSHIP_PLAN_3M_ID`, and `RAZORPAY_MEMBERSHIP_PLAN_6M_ID`. Configure the webhook URL `/api/payments/razorpay-webhook` with the exact webhook secret. Until a plan ID is configured, that plan will not charge or activate membership.
6. Subscribe to at least `subscription.authenticated`, `subscription.activated`, `subscription.charged`, `subscription.halted`, `subscription.cancelled`, `subscription.completed`, and `payment.failed`.
7. The Android UI calls the HTTPS API configured in `app/src/main/assets/config.js`; do not put secret keys in Android. Deploy the updated backend source before using new endpoints.
8. For duty acceptance, apply the updated `backend/schema.sql` to the production PostgreSQL database before deploying the updated backend. This adds `duties.accepted_by_user_id`. The app then allows logged-in driver accounts to accept an open duty; the server atomically marks it accepted so another driver cannot accept the same duty. The accepting driver can find it under **मेरी ड्यूटी → आपके द्वारा स्वीकार की गई ड्यूटी**.
8. Driver and vendor verification uploads are encrypted with AES-256-GCM before PostgreSQL storage. The encryption key is derived from `DOCUMENT_ENCRYPTION_KEY` when configured, otherwise `JWT_SECRET`. For production, set a dedicated high-entropy `DOCUMENT_ENCRYPTION_KEY` in the Render secret environment and keep it stable; changing it without re-encrypting existing records makes old uploads unreadable. Restrict admin API key access and review documents only through the protected admin endpoint.
9. Run tests for password login, single-device revocation, verification uploads/review, webhook signature validation, duplicate webhook events, membership expiry, and the 5-minute privacy rule.
10. Add a routing provider for road distance; until then distance must remain clearly marked approximate/unavailable.

## Important
The app package is a source starter. Real OTP, duty sharing, payment activation, routing and document upload require deployment/configuration and end-to-end tests. Do not advertise it as live until those are completed.
