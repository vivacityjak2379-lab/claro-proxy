const express = require('express');
const { Pool } = require('pg');
const app = express();
const PORT = process.env.PORT || 8080;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'claro-admin-2026';

// ─── DATABASE ────────────────────────────────────────────────────────────────

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
    ? { rejectUnauthorized: false }
    : false,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      uid                TEXT PRIMARY KEY,
      plan               TEXT NOT NULL DEFAULT 'free',
      email              TEXT NOT NULL DEFAULT '',
      stripe_customer_id TEXT,
      subscription_id    TEXT,
      activated_at       TIMESTAMPTZ,
      created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  console.log('✓ DB ready');
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

async function getUser(uid) {
  const { rows } = await pool.query('SELECT * FROM users WHERE uid = $1', [uid]);
  return rows[0] || null;
}

async function upsertUser(uid, fields) {
  const cols = Object.keys(fields);
  if (cols.length === 0) return;

  // Build: INSERT ... ON CONFLICT (uid) DO UPDATE SET ...
  const setClauses = cols.map((c, i) => `${c} = $${i + 2}`).join(', ');
  const values = [uid, ...cols.map(c => fields[c])];

  await pool.query(
    `INSERT INTO users (uid, ${cols.join(', ')}, updated_at)
     VALUES ($1, ${cols.map((_, i) => `$${i + 2}`).join(', ')}, NOW())
     ON CONFLICT (uid) DO UPDATE SET ${setClauses}, updated_at = NOW()`,
    values
  );
}

// ─── RATE LIMITING (in-memory, per-IP, resets on restart — acceptable) ───────

const rateLimit = {};
const RATE_WINDOW = 60 * 60 * 1000;
const RATE_MAX_FREE = 50;
const RATE_MAX_PRO  = 500;

// ─── CORS ────────────────────────────────────────────────────────────────────

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, anthropic-version, x-api-key, x-admin-password, x-uid');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Raw body for Stripe webhook must come before express.json()
app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

// ─── PROXY ───────────────────────────────────────────────────────────────────
// The frontend sends x-uid header so we can verify plan server-side.
// Free users are limited to RATE_MAX_FREE req/hr; Pro users get RATE_MAX_PRO.
// This closes the localStorage plan-spoofing vulnerability.

app.post('/v1/messages', async (req, res) => {
  const ip  = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const uid = req.headers['x-uid'] || null;
  const now = Date.now();

  // Resolve plan from DB (falls back to 'free' if uid unknown or DB error)
  let userPlan = 'free';
  if (uid) {
    try {
      const user = await getUser(uid);
      if (user) userPlan = user.plan;
    } catch (e) {
      console.error('DB plan check failed:', e.message);
    }
  }

  const rateMax = userPlan === 'pro' ? RATE_MAX_PRO : RATE_MAX_FREE;

  // Rate limit keyed by IP
  if (!rateLimit[ip]) rateLimit[ip] = { count: 0, resetAt: now + RATE_WINDOW };
  if (now > rateLimit[ip].resetAt) rateLimit[ip] = { count: 0, resetAt: now + RATE_WINDOW };
  rateLimit[ip].count++;

  if (rateLimit[ip].count > rateMax) {
    return res.status(429).json({
      error: { message: 'Rate limit exceeded. Try again in 1 hour.' }
    });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(req.body),
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

// ─── STRIPE WEBHOOK ──────────────────────────────────────────────────────────

app.post('/webhook', async (req, res) => {
  let event;
  try {
    if (STRIPE_WEBHOOK_SECRET) {
      const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
      event = stripe.webhooks.constructEvent(
        req.body,
        req.headers['stripe-signature'],
        STRIPE_WEBHOOK_SECRET
      );
    } else {
      event = JSON.parse(req.body);
    }
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed' ||
        event.type === 'customer.subscription.created') {
      const session = event.data.object;
      const uid     = session.metadata?.uid || session.client_reference_id;
      const email   = session.customer_email || session.customer_details?.email || '';

      if (uid) {
        await upsertUser(uid, {
          plan:               'pro',
          email,
          stripe_customer_id: session.customer,
          subscription_id:    session.subscription,
          activated_at:       new Date().toISOString(),
        });
        console.log(`✓ Pro activated for uid: ${uid}`);
      }
    }

    if (event.type === 'customer.subscription.deleted' ||
        event.type === 'invoice.payment_failed') {
      const subscription = event.data.object;
      const { rows } = await pool.query(
        'SELECT uid FROM users WHERE stripe_customer_id = $1',
        [subscription.customer]
      );
      if (rows.length > 0) {
        const uid = rows[0].uid;
        await pool.query(
          "UPDATE users SET plan = 'free', updated_at = NOW() WHERE uid = $1",
          [uid]
        );
        console.log(`✓ Pro cancelled for uid: ${uid}`);
      }
    }
  } catch (err) {
    console.error('Webhook DB error:', err.message);
  }

  res.json({ received: true });
});

// ─── CHECK PLAN ──────────────────────────────────────────────────────────────

app.get('/check-plan/:uid', async (req, res) => {
  try {
    const user = await getUser(req.params.uid);
    if (user) {
      res.json({ plan: user.plan, email: user.email });
    } else {
      res.json({ plan: 'free' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── REGISTER USER ───────────────────────────────────────────────────────────

app.post('/register', async (req, res) => {
  const { uid, email } = req.body;
  // plan is intentionally ignored from client — only Stripe webhook sets plan='pro'
  if (!uid) return res.status(400).json({ error: 'uid required' });

  try {
    const existing = await getUser(uid);

    if (!existing) {
      await pool.query(
        "INSERT INTO users (uid, plan, email) VALUES ($1, 'free', $2)",
        [uid, email || '']
      );
    } else if (email && !existing.email) {
      await pool.query(
        'UPDATE users SET email = $1, updated_at = NOW() WHERE uid = $2',
        [email, uid]
      );
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('/register error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── ADMIN ───────────────────────────────────────────────────────────────────

function adminAuth(req, res, next) {
  if (req.headers['x-admin-password'] !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.get('/admin/users', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users ORDER BY created_at DESC');
    res.json({ users: rows, total: rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin/users/:uid', adminAuth, async (req, res) => {
  try {
    const user = await getUser(req.params.uid);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/users/:uid/plan', adminAuth, async (req, res) => {
  const { uid } = req.params;
  const { plan } = req.body;
  if (!['free', 'pro'].includes(plan)) {
    return res.status(400).json({ error: 'Invalid plan' });
  }
  try {
    await upsertUser(uid, { plan });
    console.log(`Admin: set ${uid} to ${plan}`);
    res.json({ ok: true, uid, plan });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin/stats', adminAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        COUNT(*)                                    AS total,
        COUNT(*) FILTER (WHERE plan = 'pro')        AS pro,
        COUNT(*) FILTER (WHERE plan = 'free')       AS free
      FROM users
    `);
    res.json({
      total: Number(rows[0].total),
      pro:   Number(rows[0].pro),
      free:  Number(rows[0].free),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── HEALTH ──────────────────────────────────────────────────────────────────

app.get('/', (req, res) => res.json({ status: 'Claro proxy running', version: '3.0' }));

// ─── START ───────────────────────────────────────────────────────────────────

initDB()
  .then(() => {
    app.listen(PORT, () => console.log(`Claro proxy running on port ${PORT}`));
  })
  .catch(err => {
    console.error('Failed to init DB:', err.message);
    process.exit(1);
  });
