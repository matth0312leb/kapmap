// Vigie — API des signalements de dangers réels sur la route (Vigie).
// Pas de texte libre. La catégorie « police » (présence signalée par les conducteurs, France uniquement)
// respecte l'article L130-11 du Code de la route : POLICE_ENABLED = '0' la coupe partout, et la table
// police_block masque les signalements dans une zone et pour une durée données (suspension préfectorale).

const TYPES = {
  accident: 60,          // durée de vie en minutes
  vehicule_arrete: 45,
  objet: 60,
  bouchon: 30,
  travaux: 24 * 60,
  nid_de_poule: 7 * 24 * 60,
  meteo: 6 * 60,
  police: 60,            // France uniquement, masquable par zone (voir police_block)
  zone_danger: 60,       // France uniquement (affiché comme « zone de danger », sans précision)
};
const MAX_RADIUS_KM = 50;

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors } });

async function ipHash(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'inconnu';
  const day = new Date().toISOString().slice(0, 10);
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ip + '|' + day + '|vigie'));
  return [...new Uint8Array(buf)].slice(0, 12).map(b => b.toString(16).padStart(2, '0')).join('');
}
// ---------- Comptes : pseudo + code PIN (4 à 6 chiffres) ----------
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const randomHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));
async function hashPin(pin, salt) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode(salt), iterations: 100000 }, key, 256);
  return hex(bits);
}
function sameText(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
const WEAK_PINS = ['0000', '1111', '1234', '4321', '00000', '12345', '000000', '111111', '123456', '654321', '123123'];
function publicUser(u) {
  return { id: u.id, invites: u.invites || 0, giftUntil: u.gift_until || null, giftKind: u.gift_kind || null, plan: u.plan || null, planUntil: u.plan_until || null, planRenews: !!u.plan_renews,
    pseudo: u.pseudo, name: u.name || '', reports: u.reports_count || 0, points: u.points || 0, since: u.created_at,
    home: u.home ? JSON.parse(u.home) : null, work: u.work ? JSON.parse(u.work) : null, car: u.car ? JSON.parse(u.car) : null,
    favs: u.favs ? JSON.parse(u.favs) : null };
}
async function currentUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!/^[a-f0-9]{64}$/.test(token)) return null;
  const row = await env.DB.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?1').bind(token).first();
  if (row) await env.DB.prepare('UPDATE sessions SET last_seen = ?2 WHERE token = ?1').bind(token, Date.now()).run();
  return row ? Object.assign(row, { _token: token }) : null;
}
// ---------- Points vérifiés : un signalement ne rapporte vraiment que s'il est confirmé par un autre conducteur ----------
// Création : +2 tout de suite. Première confirmation par un autre compte (autre connexion) : +8. Confirmations suivantes : +1 (5 max).
// Signalement démenti par les autres (2 « plus là » de plus que de confirmations, sans aucune confirmation) : -2 et compté comme faux.
// 5 faux signalements sur 7 jours : plus aucun point gagné en signalant pendant 7 jours.
const PTS_CREATE = 2, PTS_CONFIRMED = 8, PTS_EXTRA = 1, EXTRA_MAX = 5;
let reportColsReady = false;
async function ensureReportCols(env) {
  if (reportColsReady) return;
  for (const col of ['confirmed INTEGER DEFAULT 0', 'paid_extra INTEGER DEFAULT 0', 'false_flag INTEGER DEFAULT 0']) {
    try { await env.DB.prepare('ALTER TABLE reports ADD COLUMN ' + col).run(); } catch (e) {}
  }
  try { await env.DB.prepare('ALTER TABLE votes ADD COLUMN ip_hash TEXT').run(); } catch (e) {}
  try { await env.DB.prepare('CREATE TABLE IF NOT EXISTS anon_votes (report_id INTEGER NOT NULL, ip_hash TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (report_id, ip_hash))').run(); } catch (e) {}
  reportColsReady = true;
}
async function falseCount(env, userId) {
  const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM reports WHERE user_id = ?1 AND false_flag = 1 AND created_at > ?2').bind(userId, Date.now() - 7 * 86400000).first();
  return r ? r.n : 0;
}
// Une confirmation d'un autre conducteur sur le signalement `rep` : paie l'auteur
async function payConfirmation(env, rep, voter) {
  if (!rep.user_id) return;
  // Anti-triche : seules les confirmations d'un compte de plus de 7 jours rapportent des points à l'auteur
  if (!voter || !voter.created_at || Date.now() - voter.created_at < 7 * DAY) return;
  if (!rep.confirmed) {
    await env.DB.prepare('UPDATE reports SET confirmed = 1 WHERE id = ?1').bind(rep.id).run();
    await addPoints(env, rep.user_id, PTS_CONFIRMED, 'confirmé');
    // Parrainage : le parrain gagne 15 points au premier signalement confirmé de son filleul (une seule fois)
    try {
      const f = await env.DB.prepare('SELECT referred_by, ref_paid FROM users WHERE id = ?1').bind(rep.user_id).first();
      if (f && f.referred_by && !f.ref_paid) {
        await env.DB.prepare('UPDATE users SET ref_paid = 1 WHERE id = ?1').bind(rep.user_id).run();
        await addPoints(env, f.referred_by, 15, 'parrainage');
      }
    } catch (e) {}
  } else if ((rep.paid_extra || 0) < EXTRA_MAX) {
    await env.DB.prepare('UPDATE reports SET paid_extra = paid_extra + 1 WHERE id = ?1').bind(rep.id).run();
    await addPoints(env, rep.user_id, PTS_EXTRA, 'confirmé');
  }
}

// ---------- Points (plafond quotidien contre les abus) ----------
const DAILY_CAP = 300;
async function addPoints(env, userId, pts, reason) {
  const now = Date.now();
  const day = await env.DB.prepare('SELECT COALESCE(SUM(pts), 0) AS n FROM points_log WHERE user_id = ?1 AND at > ?2').bind(userId, now - 86400000).first();
  const give = Math.min(pts, Math.max(0, DAILY_CAP - (day ? day.n : 0)));
  if (give <= 0) return 0;
  await env.DB.prepare('INSERT INTO points_log (user_id, pts, reason, at) VALUES (?1, ?2, ?3, ?4)').bind(userId, give, reason, now).run();
  await env.DB.prepare('UPDATE users SET points = points + ?2 WHERE id = ?1').bind(userId, give).run();
  return give;
}

async function newSession(env, userId) {
  const token = randomHex(32);
  const now = Date.now();
  await env.DB.prepare('INSERT INTO sessions (token, user_id, created_at, last_seen) VALUES (?1, ?2, ?3, ?3)').bind(token, userId, now).run();
  return token;
}
function cleanPlace(p) {
  if (!p || typeof p !== 'object') return null;
  const lat = Number(p.lat), lon = Number(p.lon);
  if (!validCoord(lat, lon)) return null;
  return JSON.stringify({ lat, lon, short: String(p.short || '').slice(0, 60), title: String(p.title || '').slice(0, 80), sub: String(p.sub || '').slice(0, 120) });
}

// Décodage des entités HTML (y compris doublement encodées : &amp;#xE9;)
function decodeEntities(t) {
  let out = String(t || '');
  for (let k = 0; k < 2; k++) {
    out = out.replace(/&amp;/g, '&')
      .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
      .replace(/&#([0-9]+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
      .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&nbsp;/g, ' ');
  }
  return out.replace(/\u00a0/g, ' ').replace(/<[^>]+>/g, '');
}

const validCoord = (lat, lon) => Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180;

// ----- Compteur d'appels TomTom (quota gratuit : 2 500 requêtes/jour hors tuiles, 50 000 tuiles/jour) -----
let usageReady = false;
async function ttFetch(env, kind, u, opts) {
  const r = await fetch(u, opts);
  try {
    if (r.headers.get('cf-cache-status') !== 'HIT' && env.DB) {
      if (!usageReady) { await env.DB.prepare('CREATE TABLE IF NOT EXISTS usage (day TEXT, kind TEXT, n INTEGER, PRIMARY KEY (day, kind))').run(); usageReady = true; }
      const day = new Date().toISOString().slice(0, 10);
      await env.DB.prepare('INSERT INTO usage (day, kind, n) VALUES (?1, ?2, 1) ON CONFLICT(day, kind) DO UPDATE SET n = n + 1').bind(day, kind).run();
    }
  } catch (e) {}
  return r;
}

// ----- Parrainage -----
// Essai : après la bêta, chaque nouveau compte a 48 h de Premium, une seule fois par appareil (identifiant d'appareil
// gardé par le navigateur) : recréer un compte sur la même voiture ne redonne pas d'essai.
// Parrain : 1 mois offert pour chaque filleul qui paie pour la première fois (quelle que soit la formule), sans limite de filleuls.
const BETA_END = Date.parse('2027-01-01T00:00:00+01:00');
const DAY = 86400000;
async function giveGift(env, userId, days, kind) {
  await env.DB.prepare('UPDATE users SET gift_until = MAX(COALESCE(gift_until, 0), ?2, ?3) + ?4, gift_kind = ?5 WHERE id = ?1')
    .bind(userId, Date.now(), BETA_END, days * DAY, kind).run();
}
async function rewardGodfather(env, filleulId) {
  // ref_reward_used est posé sur le filleul : son parrain n'est récompensé qu'une fois pour lui
  const f = await env.DB.prepare('SELECT referred_by, ref_reward_used FROM users WHERE id = ?1').bind(filleulId).first();
  if (!f || !f.referred_by || f.ref_reward_used) return;
  const g = await env.DB.prepare('SELECT id FROM users WHERE id = ?1').bind(f.referred_by).first();
  if (!g) return;
  await env.DB.prepare('UPDATE users SET ref_reward_used = 1 WHERE id = ?1').bind(filleulId).run();
  await giveGift(env, g.id, 31, 'parrainage');
}

// ----- Abonnements (colonnes ajoutées à la table users au premier besoin) -----
let billingReady = false;
async function ensureBilling(env) {
  if (billingReady) return;
  for (const col of ['plan TEXT', 'plan_until INTEGER', 'plan_renews INTEGER', 'stripe_customer TEXT', 'stripe_sub TEXT', 'referred_by INTEGER', 'ref_paid INTEGER DEFAULT 0', 'gift_until INTEGER', 'gift_kind TEXT', 'ref_reward_used INTEGER']) {
    try { await env.DB.prepare('ALTER TABLE users ADD COLUMN ' + col).run(); } catch (e) {}
  }
  billingReady = true;
}
// Vérifie la signature d'un événement Stripe (en-tête Stripe-Signature, HMAC-SHA256, 5 min de tolérance)
async function stripeVerify(raw, header, secret) {
  const parts = {}; (header || '').split(',').forEach(kv => { const i = kv.indexOf('='); if (i > 0) (parts[kv.slice(0, i)] = parts[kv.slice(0, i)] || []).push(kv.slice(i + 1)); });
  const t = parts.t && parts.t[0]; if (!t || !parts.v1) return false;
  if (Math.abs(Date.now() / 1000 - Number(t)) > 300) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(t + '.' + raw));
  const hex = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
  return parts.v1.some(v => sameText(v, hex));
}
async function stripeGet(env, path) {
  if (!env.STRIPE_SECRET_KEY) return null;
  const r = await fetch('https://api.stripe.com/v1/' + path, { headers: { Authorization: 'Bearer ' + env.STRIPE_SECRET_KEY } });
  return r.ok ? r.json() : null;
}
// Fin de période et formule d'un abonnement Stripe (champs à la racine ou dans items selon la version d'API)
function subInfo(sub) {
  const it = sub && sub.items && sub.items.data && sub.items.data[0];
  const end = (sub && sub.current_period_end) || (it && it.current_period_end) || null;
  const interval = it && it.price && it.price.recurring && it.price.recurring.interval;
  return { until: end ? end * 1000 : null, plan: interval === 'year' ? 'year' : 'month',
    renews: !(sub && (sub.cancel_at_period_end || sub.cancel_at)) && sub && sub.status !== 'canceled' };
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });
    const url = new URL(request.url);
    const now = Date.now();

    try {
      // ----- Comptes -----
      if (request.method === 'POST' && url.pathname === '/auth/register') {
        const b = await request.json().catch(() => ({}));
        const pseudo = String(b.pseudo || '').trim(), name = String(b.name || '').trim().slice(0, 30), pin = String(b.pin || '');
        if (!/^[A-Za-z0-9_.-]{3,20}$/.test(pseudo)) return json({ error: 'Pseudo : 3 à 20 caractères (lettres, chiffres, . _ -)' }, 400);
        if (!/^\d{4,6}$/.test(pin)) return json({ error: 'Le code doit faire 4 à 6 chiffres' }, 400);
        if (WEAK_PINS.includes(pin) || /^(\d)\1+$/.test(pin)) return json({ error: 'Code trop simple, choisis-en un autre' }, 400);
        const who = 'reg:' + await ipHash(request);
        const reg = await env.DB.prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE pseudo = ?1 AND at > ?2').bind(who, now - 3600000).first();
        if (reg && reg.n >= 5) return json({ error: 'Trop de comptes créés, réessaie plus tard' }, 429);
        await env.DB.prepare('INSERT INTO login_attempts (pseudo, at, ok) VALUES (?1, ?2, 1)').bind(who, now).run();
        const exists = await env.DB.prepare('SELECT id FROM users WHERE pseudo = ?1').bind(pseudo).first();
        if (exists) return json({ error: 'Ce pseudo est déjà pris' }, 409);
        const salt = randomHex(16), h = await hashPin(pin, salt);
        const res = await env.DB.prepare('INSERT INTO users (pseudo, name, pin_hash, salt, created_at) VALUES (?1, ?2, ?3, ?4, ?5)').bind(pseudo, name, h, salt, now).run();
        const id = res.meta.last_row_id;
        // Parrainage : lien ?invite=<pseudo du parrain>
        const inv = String(b.invite || '').trim();
        if (/^[A-Za-z0-9_.-]{3,20}$/.test(inv) && inv !== pseudo) {
          await ensureBilling(env);
          const godfather = await env.DB.prepare('SELECT id FROM users WHERE pseudo = ?1').bind(inv).first();
          if (godfather) {
            await env.DB.prepare('UPDATE users SET referred_by = ?2 WHERE id = ?1').bind(id, godfather.id).run();
          }
        }
        // Essai de 48 h (après la bêta), une fois par appareil
        if (now >= BETA_END) {
          const dev = String(b.device || '').replace(/[^a-f0-9]/g, '').slice(0, 40);
          await ensureBilling(env);
          await env.DB.prepare('CREATE TABLE IF NOT EXISTS trial_devices (device TEXT PRIMARY KEY, user_id INTEGER, at INTEGER)').run();
          const used = dev.length >= 16 ? await env.DB.prepare('SELECT 1 FROM trial_devices WHERE device = ?1').bind(dev).first() : true;
          if (!used) {
            await env.DB.prepare('INSERT INTO trial_devices (device, user_id, at) VALUES (?1, ?2, ?3)').bind(dev, id, now).run();
            await env.DB.prepare('UPDATE users SET gift_until = ?2, gift_kind = ?3 WHERE id = ?1').bind(id, now + 2 * DAY, 'essai').run();
          }
        }
        const token = await newSession(env, id);
        const u = await env.DB.prepare('SELECT * FROM users WHERE id = ?1').bind(id).first();
        // Alerte instantanée sur Discord (secret DISCORD_WEBHOOK = adresse du webhook du salon)
        if (env.DISCORD_WEBHOOK) {
          try {
            const total = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
            const dr = await fetch(env.DISCORD_WEBHOOK.trim(), { method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ content: 'Nouveau compte KapMap : **' + pseudo + '**' + (inv ? ' (invité par ' + inv + ')' : '') + ' · ' + (total ? total.n : '?') + ' comptes au total' }) });
            await env.DB.prepare("INSERT OR REPLACE INTO kv_state (k, v) VALUES ('discord_last_status', ?1)").bind(dr.status).run();
          } catch (e) { try { await env.DB.prepare("INSERT OR REPLACE INTO kv_state (k, v) VALUES ('discord_last_status', -1)").run(); } catch (e2) {} }
        } else {
          try { await env.DB.prepare("INSERT OR REPLACE INTO kv_state (k, v) VALUES ('discord_last_status', 0)").run(); } catch (e) {}
        }
        return json({ token, user: publicUser(u) });
      }
      if (request.method === 'POST' && url.pathname === '/auth/login') {
        const b = await request.json().catch(() => ({}));
        const pseudo = String(b.pseudo || '').trim(), pin = String(b.pin || '');
        const fails = await env.DB.prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE pseudo = ?1 AND ok = 0 AND at > ?2').bind(pseudo, now - 900000).first();
        if (fails && fails.n >= 5) return json({ error: 'Trop d\'essais, réessaie dans 15 minutes' }, 429);
        const u = await env.DB.prepare('SELECT * FROM users WHERE pseudo = ?1').bind(pseudo).first();
        const good = u && /^\d{4,6}$/.test(pin) && sameText(await hashPin(pin, u.salt), u.pin_hash);
        await env.DB.prepare('INSERT INTO login_attempts (pseudo, at, ok) VALUES (?1, ?2, ?3)').bind(pseudo, now, good ? 1 : 0).run();
        await env.DB.prepare('DELETE FROM login_attempts WHERE at < ?1').bind(now - 86400000).run();
        if (!good) return json({ error: 'Pseudo ou code incorrect' }, 401);
        const token = await newSession(env, u.id);
        return json({ token, user: publicUser(u) });
      }
      if (url.pathname === '/auth/logout' && request.method === 'POST') {
        const u = await currentUser(request, env);
        if (u) await env.DB.prepare('DELETE FROM sessions WHERE token = ?1').bind(u._token).run();
        return json({ ok: true });
      }
      // Suppression du compte (droit à l'effacement) : compte, sessions et points ; les signalements restent anonymes
      if (url.pathname === '/me' && request.method === 'DELETE') {
        const u = await currentUser(request, env);
        if (!u) return json({ error: 'Non connecté' }, 401);
        const st = [
          env.DB.prepare('DELETE FROM sessions WHERE user_id = ?1').bind(u.id),
          env.DB.prepare('DELETE FROM points_log WHERE user_id = ?1').bind(u.id),
          env.DB.prepare('UPDATE reports SET user_id = NULL WHERE user_id = ?1').bind(u.id),
          env.DB.prepare('DELETE FROM users WHERE id = ?1').bind(u.id),
        ];
        await env.DB.batch(st);
        try { await env.DB.prepare('UPDATE feedback SET user_id = NULL, pseudo = NULL WHERE user_id = ?1').bind(u.id).run(); } catch (e) {}
        return json({ ok: true });
      }
      // ----- Stripe : paiements et abonnements (mensuel / annuel récurrents, accès à vie en paiement unique) -----
      if (request.method === 'POST' && url.pathname === '/stripe/webhook') {
        if (!env.STRIPE_WEBHOOK_SECRET) return json({ error: 'Non configuré' }, 503);
        const raw = await request.text();
        if (!(await stripeVerify(raw, request.headers.get('Stripe-Signature'), env.STRIPE_WEBHOOK_SECRET))) return json({ error: 'Signature invalide' }, 400);
        const ev = JSON.parse(raw), o = ev.data && ev.data.object || {};
        await ensureBilling(env);
        if (ev.type === 'checkout.session.completed') {
          const uid = parseInt(o.client_reference_id || '', 10);
          if (uid > 0) {
            if (o.mode === 'payment') {
              await env.DB.prepare('UPDATE users SET plan = ?2, plan_until = ?3, plan_renews = 0, stripe_customer = COALESCE(?4, stripe_customer) WHERE id = ?1')
                .bind(uid, 'life', 4102444800000, o.customer || null).run();
              await rewardGodfather(env, uid);
            } else if (o.mode === 'subscription') {
              const sub = o.subscription ? await stripeGet(env, 'subscriptions/' + o.subscription) : null, si = subInfo(sub);
              await env.DB.prepare('UPDATE users SET plan = ?2, plan_until = ?3, plan_renews = ?4, stripe_customer = ?5, stripe_sub = ?6 WHERE id = ?1')
                .bind(uid, sub ? si.plan : 'month', si.until || (now + 31 * 86400000), si.renews ? 1 : 0, o.customer || null, o.subscription || null).run();
              await rewardGodfather(env, uid);
            }
          }
        } else if (ev.type === 'customer.subscription.updated' || ev.type === 'customer.subscription.deleted' || ev.type === 'customer.subscription.created') {
          const si = subInfo(o);
          const until = ev.type === 'customer.subscription.deleted' ? ((o.ended_at || o.canceled_at || now / 1000) * 1000) : si.until;
          await env.DB.prepare('UPDATE users SET plan = ?2, plan_until = COALESCE(?3, plan_until), plan_renews = ?4, stripe_sub = ?5 WHERE stripe_customer = ?1 AND (plan IS NULL OR plan != \'life\')')
            .bind(o.customer, si.plan, until, ev.type === 'customer.subscription.deleted' ? 0 : (si.renews ? 1 : 0), o.id).run();
        } else if (ev.type === 'invoice.paid') {
          const ln = o.lines && o.lines.data && o.lines.data[0];
          const end = ln && ln.period && ln.period.end;
          if (end && o.customer) await env.DB.prepare('UPDATE users SET plan_until = MAX(COALESCE(plan_until, 0), ?2) WHERE stripe_customer = ?1 AND (plan IS NULL OR plan != \'life\')').bind(o.customer, end * 1000).run();
        }
        return json({ received: true });
      }

      if (url.pathname === '/me' && request.method === 'GET') {
        await ensureBilling(env);
        const mu = await currentUser(request, env);
        if (mu) {
          const ic = await env.DB.prepare('SELECT COUNT(*) AS n FROM users WHERE referred_by = ?1').bind(mu.id).first();
          return json({ user: publicUser(Object.assign({}, mu, { invites: ic ? ic.n : 0 })) });
        }
        const u = await currentUser(request, env);
        if (!u) return json({ error: 'Non connecté' }, 401);
        return json({ user: publicUser(u) });
      }
      if (url.pathname === '/me/car' && request.method === 'PUT') {
        const u = await currentUser(request, env);
        if (!u) return json({ error: 'Non connecté' }, 401);
        const b = await request.json().catch(() => ({}));
        const model = ['3', 'Y', 'S', 'X', 'CT', 'city', 'sedan', 'suv', 'wagon', 'van'].includes(b.model) ? b.model : '3';
        const label = String(b.label || '').replace(/[<>]/g, '').trim().slice(0, 30);
        const color = /^#[0-9a-fA-F]{6}$/.test(b.color || '') ? b.color : '#f2f2f2';
        const networks = Array.isArray(b.networks) ? b.networks.filter(n => typeof n === 'string' && n.length <= 30).slice(0, 40) : undefined;
        const prev = u.car ? JSON.parse(u.car) : {};
        await env.DB.prepare('UPDATE users SET car = ?2 WHERE id = ?1').bind(u.id, JSON.stringify({ model, color, label, networks: networks || prev.networks })).run();
        return json({ ok: true });
      }
      // Favoris (parents, amis, lieux visités…) : 30 au maximum, avec un nom choisi
      if (url.pathname === '/me/favs' && request.method === 'PUT') {
        const u = await currentUser(request, env);
        if (!u) return json({ error: 'Non connecté' }, 401);
        const b = await request.json().catch(() => ({}));
        try { await env.DB.prepare('ALTER TABLE users ADD COLUMN favs TEXT').run(); } catch (e) {}
        const favs = (Array.isArray(b.favs) ? b.favs : []).slice(0, 30).map(f => {
          const c = cleanPlace(f); if (!c) return null;
          const o = JSON.parse(c); o.name = String(f.name || o.short || 'Favori').replace(/[<>]/g, '').trim().slice(0, 40); return o;
        }).filter(Boolean);
        await env.DB.prepare('UPDATE users SET favs = ?2 WHERE id = ?1').bind(u.id, JSON.stringify(favs)).run();
        return json({ ok: true, favs });
      }
      if (url.pathname === '/me/places' && request.method === 'PUT') {
        const u = await currentUser(request, env);
        if (!u) return json({ error: 'Non connecté' }, 401);
        const b = await request.json().catch(() => ({}));
        const home = 'home' in b ? cleanPlace(b.home) : u.home, work = 'work' in b ? cleanPlace(b.work) : u.work;
        await env.DB.prepare('UPDATE users SET home = ?2, work = ?3 WHERE id = ?1').bind(u.id, home, work).run();
        return json({ ok: true });
      }

      // Mes amis : mon parrain et mes filleuls (pseudo, voiture, points, signalements, ancienneté)
      if (request.method === 'GET' && url.pathname === '/me/friends') {
        const u = await currentUser(request, env);
        if (!u) return json({ error: 'Non connecté' }, 401);
        await ensureBilling(env);
        const cols = 'id, pseudo, car, points, reports_count, created_at, ref_reward_used';
        const kids = (await env.DB.prepare('SELECT ' + cols + ' FROM users WHERE referred_by = ?1 ORDER BY created_at DESC LIMIT 100').bind(u.id).all()).results || [];
        const dad = u.referred_by ? await env.DB.prepare('SELECT ' + cols + ' FROM users WHERE id = ?1').bind(u.referred_by).first() : null;
        const pub = x => ({ pseudo: x.pseudo, car: x.car ? JSON.parse(x.car) : null, points: x.points || 0, reports: x.reports_count || 0, since: x.created_at, rewarded: !!x.ref_reward_used });
        return json({ parrain: dad ? pub(dad) : null, filleuls: kids.map(pub) });
      }

      // Administration : liste des membres, réservée au compte de l'éditeur (ADMIN_ID, par défaut le compte n°1)
      if (request.method === 'GET' && url.pathname === '/admin/users') {
        const u = await currentUser(request, env);
        if (!u || u.id !== Number(env.ADMIN_ID || 1)) return json({ error: 'Accès réservé' }, 403);
        await ensureBilling(env);
        const rows = (await env.DB.prepare(`SELECT u.id, u.pseudo, u.created_at, u.reports_count, u.points, u.car, u.plan, u.plan_until, u.gift_until,
            p.pseudo AS parrain, (SELECT MAX(COALESCE(s.last_seen, s.created_at)) FROM sessions s WHERE s.user_id = u.id) AS last_seen,
            (SELECT COUNT(*) FROM users f WHERE f.referred_by = u.id) AS filleuls
          FROM users u LEFT JOIN users p ON p.id = u.referred_by ORDER BY u.created_at DESC LIMIT 500`).all()).results || [];
        return json({ total: rows.length, users: rows.map(r => Object.assign(r, { car: r.car ? JSON.parse(r.car) : null })) });
      }

      // Classement (semaine ou général) : pseudo + points uniquement
      if (request.method === 'GET' && url.pathname === '/leaderboard') {
        const week = url.searchParams.get('period') !== 'all';
        const since = now - 7 * 86400000;
        const rows = week
          ? (await env.DB.prepare('SELECT u.id, u.pseudo, SUM(p.pts) AS points FROM points_log p JOIN users u ON u.id = p.user_id WHERE p.at > ?1 GROUP BY u.id ORDER BY points DESC, u.pseudo LIMIT 20').bind(since).all()).results
          : (await env.DB.prepare('SELECT id, pseudo, points FROM users WHERE points > 0 ORDER BY points DESC, pseudo LIMIT 20').all()).results;
        const me1 = await currentUser(request, env);
        let mine = null;
        if (me1) {
          const myPts = week
            ? ((await env.DB.prepare('SELECT COALESCE(SUM(pts), 0) AS n FROM points_log WHERE user_id = ?1 AND at > ?2').bind(me1.id, since).first()) || {}).n || 0
            : me1.points || 0;
          const better = week
            ? (await env.DB.prepare('SELECT COUNT(*) AS n FROM (SELECT user_id, SUM(pts) AS s FROM points_log WHERE at > ?1 GROUP BY user_id HAVING s > ?2)').bind(since, myPts).first()).n
            : (await env.DB.prepare('SELECT COUNT(*) AS n FROM users WHERE points > ?1').bind(myPts).first()).n;
          mine = { pseudo: me1.pseudo, points: myPts, rank: myPts > 0 ? better + 1 : null };
        }
        return json({ period: week ? 'week' : 'all', top: rows.map((r, i) => ({ rank: i + 1, pseudo: r.pseudo, points: r.points, me: !!(me1 && me1.id === r.id) })), mine });
      }

      // Liste des signalements actifs autour d'un point
      if (request.method === 'GET' && url.pathname === '/reports') {
        const lat = parseFloat(url.searchParams.get('lat'));
        const lon = parseFloat(url.searchParams.get('lon'));
        const r = Math.min(parseFloat(url.searchParams.get('r') || '20'), MAX_RADIUS_KM);
        if (!validCoord(lat, lon) || !(r > 0)) return json({ error: 'Paramètres invalides' }, 400);
        const dLat = r / 111, dLon = r / (111 * Math.cos(lat * Math.PI / 180));
        const { results } = await env.DB.prepare(
          'SELECT id, lat, lon, type, created_at, expires_at, ok_votes, gone_votes FROM reports ' +
          'WHERE expires_at > ?1 AND lat BETWEEN ?2 AND ?3 AND lon BETWEEN ?4 AND ?5 ORDER BY created_at DESC LIMIT 300'
        ).bind(now, lat - dLat, lat + dLat, lon - dLon, lon + dLon).all();
        let reports = results;
        if (reports.some(x => x.type === 'police')) {
          let blocks = [];
          if (env.POLICE_ENABLED !== '0') {
            try {
              await env.DB.prepare('CREATE TABLE IF NOT EXISTS police_block (id INTEGER PRIMARY KEY AUTOINCREMENT, lat REAL, lon REAL, radius_m INTEGER, until INTEGER, note TEXT)').run();
              blocks = (await env.DB.prepare('SELECT lat, lon, radius_m FROM police_block WHERE until > ?1').bind(now).all()).results || [];
            } catch (e) {}
          }
          reports = reports.filter(x => x.type !== 'police' || (env.POLICE_ENABLED !== '0' && !blocks.some(b => hav([b.lon, b.lat], [x.lon, x.lat]) < b.radius_m)));
        }
        return json({ now, reports });
      }

      // Nouveau signalement
      if (request.method === 'POST' && url.pathname === '/reports') {
        const body = await request.json().catch(() => ({}));
        const lat = Number(body.lat), lon = Number(body.lon), type = String(body.type || '');
        if (!validCoord(lat, lon) || !TYPES[type]) return json({ error: 'Signalement invalide' }, 400);
        await ensureReportCols(env);
        if (type === 'police' && env.POLICE_ENABLED === '0') return json({ error: 'Signalement indisponible pour le moment' }, 403);
        const who = await ipHash(request);
        const recent = await env.DB.prepare(
          'SELECT COUNT(*) AS n, MAX(created_at) AS lastAt FROM reports WHERE ip_hash = ?1 AND created_at > ?2'
        ).bind(who, now - 3600000).first();
        if (recent && (recent.n >= 10 || (recent.lastAt && now - recent.lastAt < 30000))) {
          return json({ error: 'Trop de signalements, réessaie dans un moment' }, 429);
        }
        // Même danger déjà signalé à moins de 150 m : on le confirme au lieu de le dupliquer
        const d = 150 / 111000;
        const dup = await env.DB.prepare(
          'SELECT id, user_id, ip_hash, confirmed, paid_extra FROM reports WHERE type = ?1 AND expires_at > ?2 AND lat BETWEEN ?3 AND ?4 AND lon BETWEEN ?5 AND ?6 LIMIT 1'
        ).bind(type, now, lat - d, lat + d, lon - d * 1.5, lon + d * 1.5).first();
        if (dup) {
          await env.DB.prepare('UPDATE reports SET ok_votes = ok_votes + 1, expires_at = MAX(expires_at, ?2) WHERE id = ?1')
            .bind(dup.id, now + TYPES[type] * 60000).run();
          const me0 = await currentUser(request, env);
          let pts0 = 0;
          // Un autre conducteur (autre compte et autre connexion) qui signale la même chose = une confirmation
          if (dup.ip_hash !== who && (!me0 || me0.id !== dup.user_id)) {
            await payConfirmation(env, dup, me0);
            if (me0) pts0 = await addPoints(env, me0.id, 2, 'confirmation');
          }
          return json({ ok: true, id: dup.id, merged: true, points: pts0 });
        }
        const me = await currentUser(request, env);
        const res = await env.DB.prepare(
          'INSERT INTO reports (lat, lon, type, created_at, expires_at, ip_hash, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)'
        ).bind(Math.round(lat * 1e5) / 1e5, Math.round(lon * 1e5) / 1e5, type, now, now + TYPES[type] * 60000, who, me ? me.id : null).run();
        let pts1 = 0;
        if (me) {
          await env.DB.prepare('UPDATE users SET reports_count = reports_count + 1 WHERE id = ?1').bind(me.id).run();
          if ((await falseCount(env, me.id)) < 5) pts1 = await addPoints(env, me.id, PTS_CREATE, 'signalement');
        }
        await env.DB.prepare('DELETE FROM reports WHERE expires_at < ?1').bind(now - 86400000).run();
        return json({ ok: true, id: res.meta.last_row_id, points: pts1, pending: me && pts1 ? PTS_CONFIRMED : 0 });
      }

      // Vote « toujours là » / « plus là »
      const m = url.pathname.match(/^\/reports\/(\d+)\/vote$/);
      if (request.method === 'POST' && m) {
        const body = await request.json().catch(() => ({}));
        const id = Number(m[1]);
        await ensureReportCols(env);
        const row = await env.DB.prepare('SELECT id, type, ok_votes, gone_votes, user_id, ip_hash, created_at, confirmed, paid_extra, false_flag FROM reports WHERE id = ?1').bind(id).first();
        if (!row) return json({ error: 'Introuvable' }, 404);
        const voter = await currentUser(request, env), vip = await ipHash(request);
        if (vip === row.ip_hash) return json({ error: 'Tu ne peux pas confirmer ton propre signalement' }, 400);
        let pts = 0, counts = true;
        if (voter) {
          if (row.user_id === voter.id) return json({ error: 'Tu ne peux pas confirmer ton propre signalement' }, 400);
          const already = (await env.DB.prepare('SELECT 1 FROM votes WHERE report_id = ?1 AND (user_id = ?2 OR ip_hash = ?3)').bind(id, voter.id, vip).first())
            || (await env.DB.prepare('SELECT 1 FROM anon_votes WHERE report_id = ?1 AND ip_hash = ?2').bind(id, vip).first());
          if (already) return json({ error: 'Tu as déjà donné ton avis sur ce signalement' }, 409);
          await env.DB.prepare('INSERT INTO votes (report_id, user_id, at, ip_hash) VALUES (?1, ?2, ?3, ?4)').bind(id, voter.id, now, vip).run();
          pts = await addPoints(env, voter.id, 1, 'vote');
        } else {
          // Sans compte : un seul avis par connexion, sans points
          const already = (await env.DB.prepare('SELECT 1 FROM anon_votes WHERE report_id = ?1 AND ip_hash = ?2').bind(id, vip).first())
            || (await env.DB.prepare('SELECT 1 FROM votes WHERE report_id = ?1 AND ip_hash = ?2').bind(id, vip).first());
          if (already) counts = false;
          else await env.DB.prepare('INSERT INTO anon_votes (report_id, ip_hash, at) VALUES (?1, ?2, ?3)').bind(id, vip, now).run();
        }
        if (!counts) return json({ ok: true, points: 0 });
        if (!body.gone) await payConfirmation(env, row, voter);
        if (body.gone) {
          const gone = row.gone_votes + 1;
          const expire = gone >= 2 && gone > row.ok_votes;
          // Démenti alors que personne ne l'a confirmé : faux signalement, l'auteur perd ses points de création
          if (expire && !row.confirmed && !row.false_flag && row.user_id) {
            await env.DB.prepare('UPDATE reports SET false_flag = 1 WHERE id = ?1').bind(id).run();
            await env.DB.prepare('INSERT INTO points_log (user_id, pts, reason, at) VALUES (?1, ?2, ?3, ?4)').bind(row.user_id, -PTS_CREATE, 'démenti', now).run();
            await env.DB.prepare('UPDATE users SET points = MAX(0, points - ?2) WHERE id = ?1').bind(row.user_id, PTS_CREATE).run();
          }
          await env.DB.prepare('UPDATE reports SET gone_votes = ?2' + (expire ? ', expires_at = ?3' : '') + ' WHERE id = ?1')
            .bind(...(expire ? [id, gone, now] : [id, gone])).run();
          return json({ ok: true, removed: expire, points: pts });
        }
        await env.DB.prepare('UPDATE reports SET ok_votes = ok_votes + 1, expires_at = MAX(expires_at, ?2) WHERE id = ?1')
          .bind(id, now + Math.min(TYPES[row.type], 60) * 60000).run();
        return json({ ok: true, points: pts });
      }

      // Tuiles de trafic en direct (TomTom), la clé reste sur le serveur
      const tm = url.pathname.match(/^\/traffic\/(relative0|relative0-dark)\/(\d{1,2})\/(\d+)\/(\d+)\.png$/);
      if (request.method === 'GET' && tm) {
        if (!env.TOMTOM_KEY) return new Response('Clé trafic absente', { status: 503, headers: cors });
        const [, style, z, x, y] = tm;
        if (+z < 6 || +z > 22) return new Response(null, { status: 204, headers: cors });
        const upstream = 'https://api.tomtom.com/traffic/map/4/tile/flow/' + style + '/' + z + '/' + x + '/' + y + '.png?tileSize=256&key=' + env.TOMTOM_KEY;
        const r = await ttFetch(env, 'tile', upstream, { cf: { cacheTtl: 60, cacheEverything: true } });
        if (!r.ok) return new Response(null, { status: r.status, headers: cors });
        return new Response(r.body, { headers: { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=60', ...cors } });
      }

      // Trafic en données vectorielles (dessiné par la carte, aligné sur les routes)
      const tv = url.pathname.match(/^\/trafficv\/(\d{1,2})\/(\d+)\/(\d+)\.pbf$/);
      if (request.method === 'GET' && tv) {
        if (!env.TOMTOM_KEY) return new Response('Clé trafic absente', { status: 503, headers: cors });
        const [, z, x, y] = tv;
        if (+z < 6 || +z > 22) return new Response(null, { status: 204, headers: cors });
        const upstream = 'https://api.tomtom.com/traffic/map/4/tile/flow/relative/' + z + '/' + x + '/' + y + '.pbf?key=' + env.TOMTOM_KEY;
        const r = await ttFetch(env, 'tile', upstream, { cf: { cacheTtl: 60, cacheEverything: true } });
        if (!r.ok) return new Response(null, { status: r.status, headers: cors });
        return new Response(r.body, { headers: { 'Content-Type': 'application/x-protobuf', 'Cache-Control': 'public, max-age=60', ...cors } });
      }

      // ----- Itinéraire complet (TomTom) : guidage FR, trafic, limitations, voies, options, alternatives -----
      if (request.method === 'GET' && url.pathname === '/route') {
        if (!env.TOMTOM_KEY) return json({ error: 'Clé absente' }, 503);
        const f = (url.searchParams.get('from') || '').split(',').map(Number);
        const t = (url.searchParams.get('to') || '').split(',').map(Number);
        if (!validCoord(f[0], f[1]) || !validCoord(t[0], t[1])) return json({ error: 'Paramètres invalides' }, 400);
        const avoid = (url.searchParams.get('avoid') || '').split(',').filter(a => ['tollRoads', 'motorways', 'ferries'].includes(a));
        const alts = Math.max(0, Math.min(2, parseInt(url.searchParams.get('alt') || '0', 10) || 0));
        const heading = parseInt(url.searchParams.get('heading') || '', 10);
        // étapes facultatives (ex. arrêt Superchargeur) : via=lat,lon;lat,lon
        const via = (url.searchParams.get('via') || '').split(';').filter(Boolean).slice(0, 3).map(v => v.split(',').map(Number)).filter(v => validCoord(v[0], v[1]));
        let q = 'traffic=true&routeType=fastest&travelMode=car&instructionsType=text&language=fr-FR' +
          '&sectionType=traffic&sectionType=speedLimit&sectionType=lanes&sectionType=tollRoad&maxAlternatives=' + alts;
        avoid.forEach(a => { q += '&avoid=' + a; });
        if (heading >= 0 && heading < 360) q += '&vehicleHeading=' + heading;
        if (via.length) q = q.replace(/maxAlternatives=\d/, 'maxAlternatives=0');
        const locs = [f].concat(via, [t]).map(v => v[0] + ',' + v[1]).join(':');
        const r = await ttFetch(env, 'route', 'https://api.tomtom.com/routing/1/calculateRoute/' + locs + '/json?' + q + '&key=' + env.TOMTOM_KEY);
        if (!r.ok) return json({ error: 'Itinéraire indisponible' }, 502);
        const d = await r.json();
        const routes = (d.routes || []).map(rt => {
          const pts = [];
          rt.legs.forEach(l => l.points.forEach(p => pts.push([Math.round(p.longitude * 1e5) / 1e5, Math.round(p.latitude * 1e5) / 1e5])));
          const sec = rt.sections || [];
          return {
            length: rt.summary.lengthInMeters, travel: rt.summary.travelTimeInSeconds, delay: rt.summary.trafficDelayInSeconds || 0,
            points: pts,
            instr: ((rt.guidance && rt.guidance.instructions) || []).map(i => ({
              i: i.pointIndex, off: i.routeOffsetInMeters, m: i.maneuver || '', msg: i.message || '', ex: i.roundaboutExitNumber || null,
              street: i.street || '', exit: i.exitNumber || '', sign: i.signpostText || '', roads: (i.roadNumbers || []).slice(0, 2),
              ang: typeof i.turnAngleInDecimalDegrees === 'number' ? i.turnAngleInDecimalDegrees : null })),
            speed: sec.filter(x => x.sectionType === 'SPEED_LIMIT').map(x => ({ s: x.startPointIndex, e: x.endPointIndex,
              v: x.maxSpeedLimitInKmh || x.maxSpeedLimitInKilometersPerHour || (x.speedRestrictions && x.speedRestrictions[0] && x.speedRestrictions[0].maxSpeedLimitInKilometersPerHour) || null })).filter(x => x.v),
            toll: sec.some(x => x.sectionType === 'TOLL_ROAD'),
            tollSecs: sec.filter(x => x.sectionType === 'TOLL_ROAD').map(x => [x.startPointIndex, x.endPointIndex]),
            jams: sec.filter(x => x.sectionType === 'TRAFFIC').map(x => ({ s: x.startPointIndex, e: x.endPointIndex, cat: x.simpleCategory || 'JAM', mag: x.magnitudeOfDelay || 0 })),
            lanes: sec.filter(x => x.sectionType === 'LANES').map(x => ({ s: x.startPointIndex, e: x.endPointIndex,
              l: (x.lanes || []).map(ln => ({ d: ln.directions || [], f: ln.follow || null })) })).filter(x => x.l.length > 1),
          };
        });
        if (!routes.length) return json({ error: 'Aucun itinéraire' }, 404);
        return json({ routes });
      }

      // ----- Prix des péages d'un trajet (HERE Routing v8 : import du tracé puis calcul des péages) -----
      if (request.method === 'POST' && url.pathname === '/tolls') {
        if (!env.HERE_KEY) return json({ error: 'Clé absente' }, 503);
        let body; try { body = await request.json(); } catch (e) { return json({ error: 'Requête invalide' }, 400); }
        const pts = Array.isArray(body.pts) ? body.pts.filter(p => Array.isArray(p) && validCoord(p[1], p[0])) : [];
        if (pts.length < 2 || pts.length > 20000) return json({ error: 'Tracé invalide' }, 400);
        // Allègement du tracé : un point tous les ~200 m minimum, 800 points au plus
        let total = 0;
        for (let i = 1; i < pts.length; i++) total += hav(pts[i - 1], pts[i]);
        const step = Math.max(200, total / 800);
        const trace = [{ lat: pts[0][1], lng: pts[0][0] }];
        let acc = 0;
        for (let i = 1; i < pts.length - 1; i++) { acc += hav(pts[i - 1], pts[i]); if (acc >= step) { trace.push({ lat: pts[i][1], lng: pts[i][0] }); acc = 0; } }
        trace.push({ lat: pts[pts.length - 1][1], lng: pts[pts.length - 1][0] });
        const imp = await fetch('https://router.hereapi.com/v8/import?return=routeHandle&transportMode=car&apiKey=' + env.HERE_KEY, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ trace }) });
        if (!imp.ok) return json({ error: 'Péages indisponibles' }, 502);
        const handle = (((await imp.json()).routes || [])[0] || {}).routeHandle;
        if (!handle) return json({ error: 'Péages indisponibles' }, 502);
        const tr = await fetch('https://router.hereapi.com/v8/routes/' + encodeURIComponent(handle) + '?return=tolls&transportMode=car&currency=EUR&apiKey=' + env.HERE_KEY);
        if (!tr.ok) return json({ error: 'Péages indisponibles' }, 502);
        const td = await tr.json();
        let price = 0, count = 0, vignette = false;
        (((td.routes || [])[0] || {}).sections || []).forEach(sec => (sec.tolls || []).forEach(t => {
          // Pour chaque péage : le tarif simple le moins cher (hors abonnements et vignettes)
          // Tarif payé au guichet (espèces ou carte) en priorité, sinon n'importe quel tarif simple
          let best = null, bestAny = null;
          (t.fares || []).forEach(fa => {
            const pr = fa.convertedPrice && fa.convertedPrice.currency === 'EUR' ? fa.convertedPrice : fa.price;
            if (!pr || pr.currency !== 'EUR' || typeof pr.value !== 'number') return;
            if (fa.pass) { vignette = true; return; }
            const pm = fa.paymentMethods || [];
            const booth = !pm.length || pm.some(m => m === 'cash' || m === 'bankCard' || m === 'creditCard');
            if (booth && (best === null || pr.value < best)) best = pr.value;
            if (bestAny === null || pr.value < bestAny) bestAny = pr.value;
          });
          if (best === null) best = bestAny;
          if (best !== null) { price += best; count++; }
        }));
        return json({ price: Math.round(price * 100) / 100, count, vignette });
      }

      // ----- Incidents en temps réel autour d'une position (TomTom : accidents, véhicules en panne, météo, dangers) -----
      if (request.method === 'GET' && url.pathname === '/incidents') {
        if (!env.TOMTOM_KEY) return json({ error: 'Clé absente' }, 503);
        const lat = parseFloat(url.searchParams.get('lat')), lon = parseFloat(url.searchParams.get('lon'));
        if (!validCoord(lat, lon)) return json({ error: 'Paramètres invalides' }, 400);
        const dLat = 0.3, dLon = 0.42;   // environ 65 km × 65 km
        const bbox = [lon - dLon, lat - dLat, lon + dLon, lat + dLat].map(v => v.toFixed(4)).join(',');
        const fields = '{incidents{geometry{type,coordinates},properties{id,iconCategory,magnitudeOfDelay,events{description},from,to,roadNumbers,startTime}}}';
        const r = await ttFetch(env, 'incidents', 'https://api.tomtom.com/traffic/services/5/incidentDetails?bbox=' + bbox + '&fields=' + encodeURIComponent(fields) +
          '&language=fr-FR&categoryFilter=1,2,3,4,5,10,11,14&timeValidityFilter=present&key=' + env.TOMTOM_KEY);
        if (!r.ok) return json({ error: 'Incidents indisponibles' }, 502);
        const d = await r.json();
        const CAT = { 1: 'accident', 2: 'meteo', 3: 'objet', 4: 'meteo', 5: 'meteo', 10: 'meteo', 11: 'meteo', 14: 'vehicule_arrete' };
        const items = (d.incidents || []).map(inc => {
          const g = inc.geometry || {}, pr = inc.properties || {};
          const c = g.type === 'Point' ? g.coordinates : (g.coordinates || [])[0];
          if (!c || !CAT[pr.iconCategory]) return null;
          return { id: 'tt-' + String(pr.id || '').slice(0, 40), type: CAT[pr.iconCategory], cat: pr.iconCategory,
            lon: Math.round(c[0] * 1e5) / 1e5, lat: Math.round(c[1] * 1e5) / 1e5,
            desc: ((pr.events || [])[0] || {}).description || '', road: (pr.roadNumbers || []).join(', '),
            from: pr.from || '', to: pr.to || '', start: pr.startTime || null };
        }).filter(Boolean).slice(0, 300);
        return new Response(JSON.stringify({ items }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=60', ...cors } });
      }

      // ----- Limitation de vitesse à une position (hors guidage) -----
      if (request.method === 'GET' && url.pathname === '/speedlimit') {
        if (!env.TOMTOM_KEY) return json({ error: 'Clé absente' }, 503);
        const lat = parseFloat(url.searchParams.get('lat')), lon = parseFloat(url.searchParams.get('lon'));
        const heading = parseInt(url.searchParams.get('heading') || '', 10);
        if (!validCoord(lat, lon)) return json({ error: 'Paramètres invalides' }, 400);
        const r = await ttFetch(env, 'speedlimit', 'https://api.tomtom.com/search/2/reverseGeocode/' + lat.toFixed(5) + ',' + lon.toFixed(5) + '.json?returnSpeedLimit=true&radius=40' +
          (heading >= 0 && heading < 360 ? '&heading=' + heading : '') + '&key=' + env.TOMTOM_KEY, { cf: { cacheTtl: 3600, cacheEverything: true } });
        if (!r.ok) return json({ limit: null });
        const d = await r.json();
        const a = d.addresses && d.addresses[0] && d.addresses[0].address;
        const m = a && a.speedLimit ? String(a.speedLimit).match(/([0-9.]+)\s*(KPH|MPH)/i) : null;
        const v = m ? Math.round(parseFloat(m[1]) * (m[2].toUpperCase() === 'MPH' ? 1.609 : 1)) : null;
        return json({ limit: v, street: a ? (a.streetName || '') : '' });
      }

      // ----- Partage de trajet (lien temporaire) -----
      if (request.method === 'POST' && url.pathname === '/share') {
        const b = await request.json().catch(() => ({}));
        if (!validCoord(Number(b.lat), Number(b.lon))) return json({ error: 'Position invalide' }, 400);
        const id = randomHex(6), secret = randomHex(16);
        const owner = await currentUser(request, env);
        const data = { name: owner ? (owner.name || owner.pseudo) : String(b.name || '').slice(0, 30), dest: String(b.dest || '').slice(0, 80),
          dlat: Number(b.dlat) || null, dlon: Number(b.dlon) || null, lat: Number(b.lat), lon: Number(b.lon), eta: Number(b.eta) || null, speed: 0, arrived: false };
        await env.DB.prepare('INSERT INTO shares (id, secret, data, updated, expires) VALUES (?1, ?2, ?3, ?4, ?5)').bind(id, secret, JSON.stringify(data), now, now + 4 * 3600000).run();
        await env.DB.prepare('DELETE FROM shares WHERE expires < ?1').bind(now).run();
        return json({ id, secret });
      }
      const sh = url.pathname.match(/^\/share\/([a-f0-9]{12})$/);
      if (sh && request.method === 'PUT') {
        const b = await request.json().catch(() => ({}));
        const row = await env.DB.prepare('SELECT * FROM shares WHERE id = ?1').bind(sh[1]).first();
        if (!row || row.secret !== String(b.secret || '')) return json({ error: 'Lien inconnu' }, 404);
        const data = JSON.parse(row.data);
        if (validCoord(Number(b.lat), Number(b.lon))) { data.lat = Number(b.lat); data.lon = Number(b.lon); }
        if (b.eta) data.eta = Number(b.eta);
        data.speed = Number(b.speed) || 0;
        if (b.arrived) data.arrived = true;
        await env.DB.prepare('UPDATE shares SET data = ?2, updated = ?3, expires = ?4 WHERE id = ?1')
          .bind(sh[1], JSON.stringify(data), now, b.arrived ? now + 1800000 : row.expires).run();
        return json({ ok: true });
      }
      if (sh && request.method === 'GET') {
        const row = await env.DB.prepare('SELECT data, updated, expires FROM shares WHERE id = ?1').bind(sh[1]).first();
        if (!row || row.expires < now) return json({ error: 'Ce partage est terminé' }, 404);
        return json(Object.assign(JSON.parse(row.data), { updated: row.updated }));
      }

      // ----- Titres de l'actualité (flux RSS public, titres + liens uniquement) -----
      // ----- Suggestions et signalements de bugs envoyés depuis l'appli -----
      if (request.method === 'POST' && url.pathname === '/feedback') {
        let body; try { body = await request.json(); } catch (e) { return json({ error: 'Requête invalide' }, 400); }
        const kind = ['question', 'idee', 'bug', 'abonnement', 'autre'].includes(body.kind) ? body.kind : 'autre';
        const text = String(body.text || '').trim().slice(0, 2000);
        if (text.length < 3) return json({ error: 'Message trop court' }, 400);
        let email = String(body.email || '').trim().slice(0, 120);
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return json({ error: 'Adresse e-mail invalide' }, 400);
        await env.DB.prepare('CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, text TEXT, user_id INTEGER, pseudo TEXT, ua TEXT, version TEXT, created_at INTEGER, ip_hash TEXT)').run();
        try { await env.DB.prepare('ALTER TABLE feedback ADD COLUMN email TEXT').run(); } catch (e) {}
        await env.DB.prepare('DELETE FROM feedback WHERE created_at < ?1').bind(now - 2 * 365 * 86400000).run();
        const who = await ipHash(request);
        const recent = await env.DB.prepare('SELECT COUNT(*) AS n FROM feedback WHERE ip_hash = ?1 AND created_at > ?2').bind(who, now - 3600000).first();
        if (recent && recent.n >= 5) return json({ error: 'Trop de messages, réessaie plus tard' }, 429);
        const me = await currentUser(request, env);
        await env.DB.prepare('INSERT INTO feedback (kind, text, user_id, pseudo, ua, version, created_at, ip_hash, email) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)')
          .bind(kind, text, me ? me.id : null, me ? me.pseudo : null, String(request.headers.get('User-Agent') || '').slice(0, 200), String(body.version || '').slice(0, 20), now, who, email || null).run();
        // Copie sur Discord : salon dédié (secret DISCORD_WEBHOOK_MESSAGES), sinon le salon des inscriptions
        const hook = env.DISCORD_WEBHOOK_MESSAGES || env.DISCORD_WEBHOOK;
        if (hook) {
          const KIND = { question: 'Question', idee: 'Idée', bug: 'Bug', abonnement: 'Abonnement', autre: 'Message' };
          const head = '**' + (KIND[kind] || 'Message') + '** de ' + (me ? '**' + me.pseudo + '**' : 'un visiteur sans compte') + (email ? ' · ' + email : '');
          try {
            await fetch(hook.trim(), { method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ content: (head + '\n>>> ' + text).slice(0, 1990), allowed_mentions: { parse: [] } }) });
          } catch (e) {}
        }
        return json({ ok: true });
      }

      if (request.method === 'GET' && url.pathname === '/news') {
        const r = await fetch('https://www.francetvinfo.fr/titres.rss', { cf: { cacheTtl: 900, cacheEverything: true } });
        if (!r.ok) return json({ items: [] });
        const xml = await r.text();
        const items = [...xml.matchAll(/<item>[\s\S]*?<title>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>[\s\S]*?<link>([\s\S]*?)<\/link>/g)]
          .slice(0, 8).map(m => ({ title: decodeEntities(m[1]).trim().slice(0, 140), link: decodeEntities(m[2]).trim() }));
        return new Response(JSON.stringify({ source: 'franceinfo', items }), { headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'public, max-age=900', ...cors } });
      }

      // Trafic sur un trajet : durée réelle + tronçons ralentis
      if (request.method === 'GET' && url.pathname === '/route-traffic') {
        if (!env.TOMTOM_KEY) return json({ error: 'Clé trafic absente' }, 503);
        const f = (url.searchParams.get('from') || '').split(',').map(Number);
        const t = (url.searchParams.get('to') || '').split(',').map(Number);
        if (!validCoord(f[0], f[1]) || !validCoord(t[0], t[1])) return json({ error: 'Paramètres invalides' }, 400);
        const tt = 'https://api.tomtom.com/routing/1/calculateRoute/' + f[0] + ',' + f[1] + ':' + t[0] + ',' + t[1] +
          '/json?traffic=true&sectionType=traffic&routeType=fastest&travelMode=car&key=' + env.TOMTOM_KEY;
        const r = await ttFetch(env, 'route', tt);
        if (!r.ok) return json({ error: 'Trafic indisponible' }, 502);
        const d = await r.json();
        const route = d.routes && d.routes[0];
        if (!route) return json({ error: 'Aucun trajet' }, 404);
        const pts = [];
        route.legs.forEach(l => l.points.forEach(p => pts.push([Math.round(p.longitude * 1e5) / 1e5, Math.round(p.latitude * 1e5) / 1e5])));
        const jams = (route.sections || []).filter(s => s.sectionType === 'TRAFFIC').map(s => ({
          s: s.startPointIndex, e: s.endPointIndex, cat: s.simpleCategory || 'JAM', delay: s.delayInSeconds || 0, mag: s.magnitudeOfDelay || 0
        }));
        return json({ travel: route.summary.travelTimeInSeconds, delay: route.summary.trafficDelayInSeconds || 0, length: route.summary.lengthInMeters, points: pts, jams });
      }

      // ----- Consommation TomTom (7 derniers jours) -----
      if (request.method === 'GET' && url.pathname === '/usage') {
        let rows = [];
        try { rows = (await env.DB.prepare('SELECT day, kind, n FROM usage WHERE day >= ?1 ORDER BY day DESC').bind(new Date(now - 6 * 86400000).toISOString().slice(0, 10)).all()).results || []; } catch (e) {}
        const days = {};
        rows.forEach(r => { const d = days[r.day] || (days[r.day] = { day: r.day, appels: 0, tuiles: 0, detail: {} }); if (r.kind === 'tile') d.tuiles += r.n; else d.appels += r.n; d.detail[r.kind] = r.n; });
        const list = Object.values(days).map(d => Object.assign(d, { quota_appels: Math.round(d.appels / 2500 * 100) + ' %', quota_tuiles: Math.round(d.tuiles / 50000 * 100) + ' %' }));
        return json({ limite_gratuite: '2 500 appels + 50 000 tuiles par jour', jours: list });
      }

      if (url.pathname === '/') return json({ service: 'vigie-api', ok: true, traffic: !!env.TOMTOM_KEY });
      return json({ error: 'Introuvable' }, 404);
    } catch (e) {
      return json({ error: 'Erreur serveur' }, 500);
    }
  },
};

// Distance en mètres entre deux points [lon, lat]
function hav(a, b) {
  const R = 6371000, toR = Math.PI / 180, dLat = (b[1] - a[1]) * toR, dLon = (b[0] - a[0]) * toR;
  const x = Math.sin(dLat / 2) ** 2 + Math.cos(a[1] * toR) * Math.cos(b[1] * toR) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(x));
}
