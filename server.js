const express = require('express');
const app = express();
const PORT = process.env.PORT || 8080;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'claro-admin-2026';

// Rate limiting
const rateLimit = {};
const RATE_WINDOW = 60 * 60 * 1000; // 1 hour
const RATE_MAX = 50;

// In-memory user store (for MVP — replace with DB later)
const users = {}; // { uid: { plan, email, stripeCustomerId, createdAt } }

// CORS
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, anthropic-version, x-api-key, x-admin-password');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Raw body for Stripe webhook
app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

// ─── PROXY ───
app.post('/v1/messages', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const now = Date.now();

  if (!rateLimit[ip]) rateLimit[ip] = { count: 0, resetAt: now + RATE_WINDOW };
  if (now > rateLimit[ip].resetAt) { rateLimit[ip] = { count: 0, resetAt: now + RATE_WINDOW }; }
  rateLimit[ip].count++;

  if (rateLimit[ip].count > RATE_MAX) {
    return res.status(429).json({ error: { message: 'Rate limit exceeded. Try again in 1 hour.' } });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

// ─── STRIPE WEBHOOK ───
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

  // Handle events
  if (event.type === 'checkout.session.completed' || 
      event.type === 'customer.subscription.created') {
    const session = event.data.object;
    const uid = session.metadata?.uid || session.client_reference_id;
    const email = session.customer_email || session.customer_details?.email;
    
    if (uid) {
      users[uid] = {
        plan: 'pro',
        email: email || '',
        stripeCustomerId: session.customer,
        subscriptionId: session.subscription,
        activatedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      console.log(`✓ Pro activated for uid: ${uid}`);
    }
  }

  if (event.type === 'customer.subscription.deleted' ||
      event.type === 'invoice.payment_failed') {
    const subscription = event.data.object;
    // Find user by stripeCustomerId
    const uid = Object.keys(users).find(
      k => users[k].stripeCustomerId === subscription.customer
    );
    if (uid) {
      users[uid].plan = 'free';
      users[uid].updatedAt = new Date().toISOString();
      console.log(`✓ Pro cancelled for uid: ${uid}`);
    }
  }

  res.json({ received: true });
});

// ─── CHECK PLAN (called from app) ───
app.get('/check-plan/:uid', (req, res) => {
  const { uid } = req.params;
  const user = users[uid];
  if (user) {
    res.json({ plan: user.plan, email: user.email });
  } else {
    res.json({ plan: 'free' });
  }
});

// ─── REGISTER USER ───
app.post('/register', (req, res) => {
  const { uid, email } = req.body;
  if (!uid) return res.status(400).json({ error: 'uid required' });
  if (!users[uid]) {
    users[uid] = {
      plan: 'free',
      email: email || '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
  } else if (email && !users[uid].email) {
    users[uid].email = email;
  }
  res.json({ ok: true });
});

// ─── ADMIN API ───
function adminAuth(req, res, next) {
  const auth = req.headers['x-admin-password'];
  if (auth !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// Get all users
app.get('/admin/users', adminAuth, (req, res) => {
  const list = Object.entries(users).map(([uid, data]) => ({ uid, ...data }));
  res.json({ users: list, total: list.length });
});

// Get user by UID
app.get('/admin/users/:uid', adminAuth, (req, res) => {
  const user = users[req.params.uid];
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ uid: req.params.uid, ...user });
});

// Set plan manually
app.post('/admin/users/:uid/plan', adminAuth, (req, res) => {
  const { uid } = req.params;
  const { plan } = req.body;
  if (!['free', 'pro'].includes(plan)) return res.status(400).json({ error: 'Invalid plan' });
  if (!users[uid]) users[uid] = { plan, email: '', createdAt: new Date().toISOString() };
  users[uid].plan = plan;
  users[uid].updatedAt = new Date().toISOString();
  console.log(`Admin: set ${uid} to ${plan}`);
  res.json({ ok: true, uid, plan });
});

// Stats
app.get('/admin/stats', adminAuth, (req, res) => {
  const total = Object.keys(users).length;
  const pro = Object.values(users).filter(u => u.plan === 'pro').length;
  res.json({ total, pro, free: total - pro });
});

app.get('/', (req, res) => res.json({ status: 'Claro proxy running', version: '2.0' }));

app.listen(PORT, () => console.log(`Claro proxy running on port ${PORT}`));
