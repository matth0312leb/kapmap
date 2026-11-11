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
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors } });

async function ipHash(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'inconnu';
  const day = new Date().toISOString().slice(0, 10);
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ip + '|' + day + '|vigie'));
  return [...new Uint8Array(buf)].slice(0, 12).map(b => b.toString(16).padStart(2, '0')).join('');
}
const validCoord = (lat, lon) => Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180;

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });
    const url = new URL(request.url);
    const now = Date.now();

    try {
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
        const res = await env.DB.prepare(
          'INSERT INTO reports (lat, lon, type, created_at, expires_at, ip_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)'
        ).bind(Math.round(lat * 1e5) / 1e5, Math.round(lon * 1e5) / 1e5, type, now, now + TYPES[type] * 60000, who).run();
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

      if (url.pathname === '/') return json({ service: 'vigie-api', ok: true, traffic: !!env.TOMTOM_KEY });
      return json({ error: 'Introuvable' }, 404);
    } catch (e) {
      return json({ error: 'Erreur serveur' }, 500);
    }
  },
};
