// Vigie — API des signalements de dangers réels sur la route (Vigie).
// Pas de texte libre et aucune catégorie « police » ou « contrôle » :
// seuls des dangers matériels peuvent être signalés.

const TYPES = {
  accident: 60,          // durée de vie en minutes
  vehicule_arrete: 45,
  objet: 60,
  bouchon: 30,
  travaux: 24 * 60,
  nid_de_poule: 7 * 24 * 60,
  meteo: 6 * 60,
};
const MAX_RADIUS_KM = 50;

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
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
  return { pseudo: u.pseudo, name: u.name || '', reports: u.reports_count || 0, since: u.created_at,
    home: u.home ? JSON.parse(u.home) : null, work: u.work ? JSON.parse(u.work) : null };
}
async function currentUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!/^[a-f0-9]{64}$/.test(token)) return null;
  const row = await env.DB.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?1').bind(token).first();
  if (row) await env.DB.prepare('UPDATE sessions SET last_seen = ?2 WHERE token = ?1').bind(token, Date.now()).run();
  return row ? Object.assign(row, { _token: token }) : null;
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

const validCoord = (lat, lon) => Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180;

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
        const token = await newSession(env, id);
        const u = await env.DB.prepare('SELECT * FROM users WHERE id = ?1').bind(id).first();
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
      if (url.pathname === '/me' && request.method === 'GET') {
        const u = await currentUser(request, env);
        if (!u) return json({ error: 'Non connecté' }, 401);
        return json({ user: publicUser(u) });
      }
      if (url.pathname === '/me/places' && request.method === 'PUT') {
        const u = await currentUser(request, env);
        if (!u) return json({ error: 'Non connecté' }, 401);
        const b = await request.json().catch(() => ({}));
        const home = 'home' in b ? cleanPlace(b.home) : u.home, work = 'work' in b ? cleanPlace(b.work) : u.work;
        await env.DB.prepare('UPDATE users SET home = ?2, work = ?3 WHERE id = ?1').bind(u.id, home, work).run();
        return json({ ok: true });
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
        return json({ now, reports: results });
      }

      // Nouveau signalement
      if (request.method === 'POST' && url.pathname === '/reports') {
        const body = await request.json().catch(() => ({}));
        const lat = Number(body.lat), lon = Number(body.lon), type = String(body.type || '');
        if (!validCoord(lat, lon) || !TYPES[type]) return json({ error: 'Signalement invalide' }, 400);
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
          'SELECT id FROM reports WHERE type = ?1 AND expires_at > ?2 AND lat BETWEEN ?3 AND ?4 AND lon BETWEEN ?5 AND ?6 LIMIT 1'
        ).bind(type, now, lat - d, lat + d, lon - d * 1.5, lon + d * 1.5).first();
        if (dup) {
          await env.DB.prepare('UPDATE reports SET ok_votes = ok_votes + 1, expires_at = MAX(expires_at, ?2) WHERE id = ?1')
            .bind(dup.id, now + TYPES[type] * 60000).run();
          return json({ ok: true, id: dup.id, merged: true });
        }
        const me = await currentUser(request, env);
        const res = await env.DB.prepare(
          'INSERT INTO reports (lat, lon, type, created_at, expires_at, ip_hash, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)'
        ).bind(Math.round(lat * 1e5) / 1e5, Math.round(lon * 1e5) / 1e5, type, now, now + TYPES[type] * 60000, who, me ? me.id : null).run();
        if (me) await env.DB.prepare('UPDATE users SET reports_count = reports_count + 1 WHERE id = ?1').bind(me.id).run();
        await env.DB.prepare('DELETE FROM reports WHERE expires_at < ?1').bind(now - 86400000).run();
        return json({ ok: true, id: res.meta.last_row_id });
      }

      // Vote « toujours là » / « plus là »
      const m = url.pathname.match(/^\/reports\/(\d+)\/vote$/);
      if (request.method === 'POST' && m) {
        const body = await request.json().catch(() => ({}));
        const id = Number(m[1]);
        const row = await env.DB.prepare('SELECT type, ok_votes, gone_votes FROM reports WHERE id = ?1').bind(id).first();
        if (!row) return json({ error: 'Introuvable' }, 404);
        if (body.gone) {
          const gone = row.gone_votes + 1;
          const expire = gone >= 2 && gone > row.ok_votes;
          await env.DB.prepare('UPDATE reports SET gone_votes = ?2' + (expire ? ', expires_at = ?3' : '') + ' WHERE id = ?1')
            .bind(...(expire ? [id, gone, now] : [id, gone])).run();
          return json({ ok: true, removed: expire });
        }
        await env.DB.prepare('UPDATE reports SET ok_votes = ok_votes + 1, expires_at = MAX(expires_at, ?2) WHERE id = ?1')
          .bind(id, now + Math.min(TYPES[row.type], 60) * 60000).run();
        return json({ ok: true });
      }

      // Tuiles de trafic en direct (TomTom), la clé reste sur le serveur
      const tm = url.pathname.match(/^\/traffic\/(relative0|relative0-dark)\/(\d{1,2})\/(\d+)\/(\d+)\.png$/);
      if (request.method === 'GET' && tm) {
        if (!env.TOMTOM_KEY) return new Response('Clé trafic absente', { status: 503, headers: cors });
        const [, style, z, x, y] = tm;
        if (+z < 6 || +z > 22) return new Response(null, { status: 204, headers: cors });
        const upstream = 'https://api.tomtom.com/traffic/map/4/tile/flow/' + style + '/' + z + '/' + x + '/' + y + '.png?tileSize=256&key=' + env.TOMTOM_KEY;
        const r = await fetch(upstream, { cf: { cacheTtl: 60, cacheEverything: true } });
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
        const r = await fetch(upstream, { cf: { cacheTtl: 60, cacheEverything: true } });
        if (!r.ok) return new Response(null, { status: r.status, headers: cors });
        return new Response(r.body, { headers: { 'Content-Type': 'application/x-protobuf', 'Cache-Control': 'public, max-age=60', ...cors } });
      }

      // Trafic sur un trajet : durée réelle + tronçons ralentis
      if (request.method === 'GET' && url.pathname === '/route-traffic') {
        if (!env.TOMTOM_KEY) return json({ error: 'Clé trafic absente' }, 503);
        const f = (url.searchParams.get('from') || '').split(',').map(Number);
        const t = (url.searchParams.get('to') || '').split(',').map(Number);
        if (!validCoord(f[0], f[1]) || !validCoord(t[0], t[1])) return json({ error: 'Paramètres invalides' }, 400);
        const tt = 'https://api.tomtom.com/routing/1/calculateRoute/' + f[0] + ',' + f[1] + ':' + t[0] + ',' + t[1] +
          '/json?traffic=true&sectionType=traffic&routeType=fastest&travelMode=car&key=' + env.TOMTOM_KEY;
        const r = await fetch(tt);
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

      if (url.pathname === '/') return json({ service: 'vigie-api', ok: true, traffic: !!env.TOMTOM_KEY });
      return json({ error: 'Introuvable' }, 404);
    } catch (e) {
      return json({ error: 'Erreur serveur' }, 500);
    }
  },
};
