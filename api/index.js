import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import serverless from "serverless-http";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- Configuration ---
const LINKVERTISE_TOKEN = process.env.LINKVERTISE_TOKEN || "YOUR_LINKVERTISE_TOKEN";
const KEY_SALT = process.env.KEY_SALT || "CHANGE_ME_SALT";
const ADMIN_KEY = process.env.ADMIN_KEY || "admin-secret"; // to view generated keys (optional)

// --- In-memory storage (resets on redeploy/restart) ---
const keys = new Map();

// --- Helpers ---
function genKey() {
  const raw = crypto.randomBytes(10).toString("hex").toUpperCase();
  return raw.match(/.{1,5}/g).join("-");
}
function hashKey(key) {
  return crypto.createHmac("sha256", KEY_SALT).update(key).digest("hex");
}
async function verifyLinkvertise(hash) {
  const url = `https://publisher.linkvertise.com/api/v1/anti_bypassing?token=${encodeURIComponent(
    LINKVERTISE_TOKEN
  )}&hash=${encodeURIComponent(hash)}`;
  try {
    const res = await fetch(url, { method: "POST" });
    if (!res.ok) return false;
    const data = await res.json();
    // Adjust check depending on API structure — assume success if object
    return typeof data === "object";
  } catch (err) {
    console.error("Verification error:", err);
    return false;
  }
}

// --- Routes ---
// Home
app.get("/", (req, res) => {
  res.send(`
    <html><body style="font-family:sans-serif;text-align:center;padding:2rem">
      <h2>🔑 Key Generator System</h2>
      <p>Once a user completes your Linkvertise, they’ll be redirected to:</p>
      <code>${req.protocol}://${req.get("host")}/linkvertise/complete?hash=XYZ</code>
      <p>Set that as your Linkvertise redirect URL.</p>
    </body></html>
  `);
});

// Linkvertise redirect target
app.get("/linkvertise/complete", async (req, res) => {
  const { hash } = req.query;
  if (!hash) return res.status(400).send("Missing hash.");

  const already = keys.get(hash);
  if (already) {
    return res.send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:2rem">
        <h3>⚠️ This link has already been used.</h3>
        <p>A key was already generated for this hash.</p>
      </body></html>
    `);
  }

  const verified = await verifyLinkvertise(hash);
  if (!verified) {
    return res.status(400).send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:2rem">
        <h3>❌ Verification failed</h3>
        <p>We couldn't verify your Linkvertise completion.</p>
      </body></html>
    `);
  }

  // Generate key and record
  const plainKey = genKey();
  const keyHash = hashKey(plainKey);
  keys.set(hash, { key: keyHash, shown: true, created: Date.now() });

  res.send(`
    <html><body style="font-family:sans-serif;text-align:center;padding:2rem">
      <h2>✅ Key Generated Successfully</h2>
      <p>Copy this key (it’s shown only once):</p>
      <div style="background:#eee;display:inline-block;padding:1rem 2rem;font-size:1.5em;border-radius:8px;margin-top:1rem">
        ${plainKey}
      </div>
      <p style="margin-top:1rem">Thank you for completing the Linkvertise!</p>
    </body></html>
  `);
});

// Admin viewer (optional)
app.get("/admin", (req, res) => {
  const key = req.query.key;
  if (key !== ADMIN_KEY) return res.status(403).send("Forbidden.");
  const list = [...keys.entries()].map(([hash, data]) => ({
    hash,
    created: new Date(data.created).toISOString(),
    keyHash: data.key,
  }));
  res.json(list);
});

// Export handler for Vercel
export default serverless(app);
