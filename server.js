// Jihad Ai backend (Node 18+)
// Run: npm i express && node --env-file=.env server.js
const express = require('express');
const app = express();
app.use(express.json({ limit: '1mb' }));
app.set('trust proxy', 1); // Render and Vercel sit behind a proxy
app.use(express.static(require('path').join(__dirname, 'public'))); // serves only public/index.html

const list = v => (v || '').split(',').map(s => s.trim()).filter(Boolean);

const system = name => `You are "Jihad Ai", an AI assistant developed by "Jihad Boos". Never say you were made by OpenAI, Google, Anthropic or anyone else.
If the user asks which server or model you run on (for example "তুমি কোন সার্ভারে চলছো?"), answer honestly and directly. The engine serving this reply right now is "${name}". Example: "আমি ${name} সার্ভারে চলছি।"
Speak like a warm, friendly human friend. In Bengali always use "তুমি". Keep sentences short and natural for text-to-speech. Avoid markdown symbols like ** or ### and use them only for code blocks.
Reply in exactly the language the user writes: Bengali, English or Banglish.`;

// Read an upstream Server-Sent Events stream
async function sse(res, onData) {
  const dec = new TextDecoder();
  let buf = '';
  for await (const chunk of res.body) {
    buf += dec.decode(chunk, { stream: true });
    const parts = buf.split(/\r?\n\r?\n/);
    buf = parts.pop();
    for (const part of parts)
      for (const line of part.split(/\r?\n/))
        if (line.startsWith('data:')) {
          const d = line.slice(5).trim();
          if (d && d !== '[DONE]') try { onData(JSON.parse(d)); } catch {}
        }
  }
}
const check = r => { if (!r.ok) throw Object.assign(new Error('upstream ' + r.status), { status: r.status }); };

const openaiLike = (url, model) => async (key, sys, msgs, out) => {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + key },
    body: JSON.stringify({ model, stream: true, messages: [{ role: 'system', content: sys }, ...msgs] })
  });
  check(r);
  await sse(r, j => { const t = j.choices?.[0]?.delta?.content; if (t) out(t); });
};

const gemini = async (key, sys, msgs, out) => {
  const m = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${m}:streamGenerateContent?alt=sse`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: sys }] },
      contents: msgs.map(x => ({ role: x.role === 'assistant' ? 'model' : 'user', parts: [{ text: x.content }] }))
    })
  });
  check(r);
  await sse(r, j => {
    const t = j.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('');
    if (t) out(t);
  });
};

const claude = async (key, sys, msgs, out) => {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: process.env.CLAUDE_MODEL || 'claude-haiku-5-5', max_tokens: 1024, stream: true, system: sys, messages: msgs })
  });
  check(r);
  await sse(r, j => { if (j.type === 'content_block_delta' && j.delta?.text) out(j.delta.text); });
};

// Provider order = failover order. Keys: comma-separated in .env
const P = [
  { name: 'Google Gemini', keys: list(process.env.GEMINI_KEYS), run: gemini },
  { name: 'OpenAI', keys: list(process.env.OPENAI_KEYS), run: openaiLike('https://api.openai.com/v1/chat/completions', process.env.OPENAI_MODEL || 'gpt-4o-mini') },
  { name: 'Anthropic Claude', keys: list(process.env.ANTHROPIC_KEYS), run: claude },
  { name: process.env.CLOUD_AI_NAME || 'DeepSeek', keys: list(process.env.CLOUD_AI_KEYS),
    run: openaiLike(process.env.CLOUD_AI_URL || 'https://api.deepseek.com/chat/completions', process.env.CLOUD_AI_MODEL || 'deepseek-chat') }
].map(p => ({ ...p, i: 0, cool: {} }));

// Round-robin key rotation, skipping keys that are cooling down
function nextKey(p) {
  const now = Date.now();
  for (let n = 0; n < p.keys.length; n++) {
    const k = p.keys[(p.i + n) % p.keys.length];
    if ((p.cool[k] || 0) < now) { p.i = (p.i + n + 1) % p.keys.length; return k; }
  }
}

// ---- Password login (APP_PASSWORD in env; optional SESSION_SECRET) ----
const crypto = require('crypto');
const PASSWORD = process.env.APP_PASSWORD || '';
if (!PASSWORD) console.warn('APP_PASSWORD is not set: nobody can log in or chat');
const SECRET = process.env.SESSION_SECRET || crypto.createHash('sha256').update('jihad-ai:' + PASSWORD).digest('hex');
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const DAY = 864e5;
const makeToken = () => { const exp = Date.now() + 30 * DAY; return exp + '.' + sign(String(exp)); };
const goodToken = t => {
  const [exp, sig] = String(t || '').split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(exp));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const cookieOf = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(x => x[0]));
const authed = req => !!PASSWORD && goodToken(cookieOf(req).jai);
const needAuth = (req, res, next) => (authed(req) ? next() : res.status(401).json({ error: 'login' }));

const fails = new Map(); // wrong-password attempts per IP: 5 per 15 minutes
app.post('/api/login', (req, res) => {
  const now = Date.now();
  const f = (fails.get(req.ip) || []).filter(t => now - t < 15 * 60e3);
  if (f.length >= 5) return res.status(429).end();
  if (!PASSWORD) return res.status(503).end();
  if (!crypto.timingSafeEqual(sha(req.body?.password ?? ''), sha(PASSWORD))) {
    f.push(now); fails.set(req.ip, f);
    return res.status(401).end();
  }
  fails.delete(req.ip);
  res.cookie('jai', makeToken(), { httpOnly: true, sameSite: 'lax', secure: req.secure, maxAge: 30 * DAY });
  res.end();
});
app.get('/api/me', (req, res) => res.sendStatus(authed(req) ? 200 : 401));
app.post('/api/logout', (req, res) => { res.clearCookie('jai'); res.end(); });
app.use('/api/chat', needAuth);

// Simple rate limit: 20 messages per minute per IP
const hits = new Map();
app.use('/api/chat', (req, res, next) => {
  const now = Date.now();
  const a = (hits.get(req.ip) || []).filter(t => now - t < 60e3);
  if (a.length >= 20) return res.status(429).end();
  a.push(now);
  hits.set(req.ip, a);
  next();
});

app.get('/health', (req, res) => res.send('ok'));

app.post('/api/chat', async (req, res) => {
  const msgs = (req.body.messages || [])
    .filter(m => m && m.content)
    .slice(-20)
    .map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: String(m.content).slice(0, 8000) }));
  if (!msgs.length || msgs[0].role !== 'user') msgs.splice(0, msgs.length, ...msgs.filter(m => m.role === 'user').slice(-1));

  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.flushHeaders();
  const send = o => res.write('data: ' + JSON.stringify(o) + '\n\n');
  const end = () => { res.write('data: [DONE]\n\n'); res.end(); };
  let sent = 0;

  for (const p of P) {
    for (let tries = p.keys.length; tries > 0; tries--) {
      const key = nextKey(p);
      if (!key) break;
      try {
        await p.run(key, system(p.name), msgs, t => { sent++; send({ t }); });
        return end();
      } catch (e) {
        if (sent) return end(); // part of the reply is already on the user's screen
        const s = e.status;
        p.cool[key] = Date.now() + (s === 429 ? 60e3 : [400, 401, 403].includes(s) ? 600e3 : 15e3);
        console.warn(`[${p.name}] key failed (${s || e.message}), switching`);
      }
    }
  }
  // Every key failed: the user still gets a friendly message, never a raw API error
  send({ t: 'এই মুহূর্তে একটু ব্যস্ত আছি। কিছুক্ষণ পর আবার বলো, আমি এখানেই আছি।' });
  end();
});

app.listen(process.env.PORT || 3000, () => console.log('Jihad Ai running on http://localhost:' + (process.env.PORT || 3000)));
