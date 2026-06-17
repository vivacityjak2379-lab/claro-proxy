# Claro Proxy

Secure backend proxy for the Claro app. Keeps your Anthropic API key hidden from users.

## Deploy to Railway (recommended, free tier)

1. Push this folder to a GitHub repo
2. Go to railway.app → New Project → Deploy from GitHub
3. Select your repo
4. Go to Variables → add: `ANTHROPIC_API_KEY = sk-ant-your-key`
5. Railway auto-deploys and gives you a URL like `https://claro-proxy.up.railway.app`
6. Copy that URL into claro.html (see step below)

## Deploy to Render (alternative, also free)

1. Push to GitHub
2. render.com → New Web Service → connect repo
3. Build command: (leave empty)
4. Start command: `node server.js`
5. Add env var: `ANTHROPIC_API_KEY`
6. Deploy → copy URL

## After deploy: update claro.html

Find this line in claro.html:
```
const PROXY_URL = 'https://YOUR-PROXY-URL.up.railway.app';
```
Replace with your actual Railway/Render URL.

## What it does

- Receives requests from your Claro app
- Adds your secret API key
- Forwards to Anthropic
- Rate limits: 50 requests per IP per hour
- Forces model = claude-sonnet-4-6 (prevents abuse)
- Caps max_tokens at 1024
