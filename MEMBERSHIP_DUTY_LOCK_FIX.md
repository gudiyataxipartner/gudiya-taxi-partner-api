# Membership and duty lock fix

The API now uses one consistent membership decision for duty privacy: explicit Admin Paid/Unpaid override first; otherwise only an unexpired active verified manual UPI membership, server-issued admin extension, or server-issued referral reward qualifies. The duties endpoint includes `membershipActive` and `membershipDecisionSource` for verification. Private contact fields remain server-gated.

Deploy this API to Render before rebuilding the Android app. After deployment, verify `/api/membership` and `/api/duties` using the same signed-in account.
