"""Récupère les données publiques et produit les fichiers utilisés par l'appli.

- data/points.json : points de contrôle fixes publiés par le Ministère de l'Intérieur
  (jeu « Liste des radars fixes en France » sur data.gouv.fr), sous forme compacte.
- data/france.json : contour de la France (Natural Earth 1:10m), pour couper
  les alertes hors de France (Suisse, Allemagne, etc.).

Lancé par .github/workflows/data.yml (au push, à la main, et chaque mois).
"""
import csv
import io
import json
import os
import sys
import unicodedata
import urllib.parse
import urllib.request
from datetime import datetime, timezone

DATASET_ID = "6712583387af110196942793"  # Liste des radars fixes en France
BORDER_URLS = [
    "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_10m_admin_0_countries.geojson",
    "https://raw.githubusercontent.com/datasets/geo-countries/main/data/countries.geojson",
    "https://raw.githubusercontent.com/datasets/geo-countries/master/data/countries.geojson",
]


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "zones-app-data/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def norm(s):
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode()
    return s.strip().lower()


def to_float(v):
    if v is None:
        return None
    v = str(v).strip().replace(",", ".")
    try:
        return float(v)
    except ValueError:
        return None


def parse_csv(raw):
    for enc in ("utf-8-sig", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    sample = text[:5000]
    delim = ";" if sample.count(";") > sample.count(",") else ","
    rows = list(csv.DictReader(io.StringIO(text), delimiter=delim))
    if not rows:
        return None
    cols = {norm(c): c for c in rows[0].keys() if c}
    pick = lambda *keys: next((orig for n, orig in cols.items() if any(k in n for k in keys)), None)
    c_lat, c_lon = pick("latitude", "lat"), pick("longitude", "lon", "lng")
    c_vma = pick("vitesse", "vma", "limit")
    c_type = pick("type", "equipement")
    if not (c_lat and c_lon):
        return None
    items = []
    for r in rows:
        lat, lon = to_float(r.get(c_lat)), to_float(r.get(c_lon))
        if lat is None or lon is None or not (-90 <= lat <= 90 and -180 <= lon <= 180):
            continue
        vma = to_float(r.get(c_vma)) if c_vma else None
        vma = int(vma) if vma and 10 <= vma <= 130 else 0
        typ = norm(r.get(c_type) or "")[:12] if c_type else ""
        items.append([round(lat, 5), round(lon, 5), vma, typ])
    print(f"  colonnes : lat={c_lat} lon={c_lon} vma={c_vma} type={c_type} -> {len(items)} points")
    return items


def build_points():
    meta = json.loads(get(f"https://www.data.gouv.fr/api/1/datasets/{DATASET_ID}/"))
    resources = [r for r in meta.get("resources", []) if (r.get("format") or "").lower() == "csv"]
    resources.sort(key=lambda r: r.get("last_modified") or "", reverse=True)
    for r in resources:
        print(f"Ressource : {r.get('title')} ({r.get('last_modified')}) {r.get('url')}")
        try:
            items = parse_csv(get(r["url"]))
        except Exception as e:  # noqa: BLE001
            print(f"  échec : {e}")
            continue
        if items and len(items) > 500:
            return {
                "updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "source_date": r.get("last_modified"),
                "source": r.get("url"),
                "count": len(items),
                "items": items,
            }
    raise SystemExit("Aucune ressource exploitable trouvée")


def build_border():
    for url in BORDER_URLS:
        try:
            gj = json.loads(get(url))
        except Exception as e:  # noqa: BLE001
            print(f"Frontières : échec {url} ({e})")
            continue
        for f in gj.get("features", []):
            p = f.get("properties", {})
            codes = {str(p.get(k)) for k in ("ADM0_A3", "ISO_A3", "ISO3166-1-Alpha-3")}
            if "FRA" in codes:
                g = f["geometry"]
                polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
                rings = []
                for poly in polys:
                    outer = poly[0]
                    flat = []
                    for lon, lat in outer:
                        flat += [round(lon, 5), round(lat, 5)]
                    rings.append(flat)
                print(f"Frontières : {len(rings)} polygones depuis {url}")
                return {"source": url, "rings": rings}
    raise SystemExit("Contour de la France introuvable")


BANNED = ["CHE", "DEU"]  # pays où toute alerte est interdite


def flatten_geometry(g, min_step_m=15):
    """Anneaux extérieurs en liste plate [lon, lat, ...], points trop proches retirés."""
    polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
    rings = []
    for poly in polys:
        flat, last = [], None
        for lon, lat in poly[0]:
            if last:
                dx = (lon - last[0]) * 111320 * 0.69
                dy = (lat - last[1]) * 110540
                if dx * dx + dy * dy < min_step_m * min_step_m:
                    continue
            flat += [round(lon, 5), round(lat, 5)]
            last = (lon, lat)
        if len(flat) >= 8:
            rings.append(flat)
    return rings


def build_banned():
    """Contours précis (geoBoundaries) des pays où les alertes sont interdites."""
    out = {}
    for iso in BANNED:
        meta = json.loads(get(f"https://www.geoboundaries.org/api/current/gbOpen/{iso}/ADM0/"))
        for key in ("gjDownloadURL", "simplifiedGeometryGeoJSON"):
            url = meta.get(key)
            if not url:
                continue
            try:
                gj = json.loads(get(url))
                rings = []
                for f in gj["features"]:
                    rings += flatten_geometry(f["geometry"])
                pts = sum(len(r) // 2 for r in rings)
                print(f"{iso} : {len(rings)} polygones, {pts} points ({key})")
                out[iso] = rings
                break
            except Exception as e:  # noqa: BLE001
                print(f"{iso} : échec {key} ({e})")
        if iso not in out:
            raise SystemExit(f"Contour précis introuvable pour {iso}")
    return out


def build_superchargers():
    """Superchargeurs ouverts en Europe (base communautaire supercharge.info)."""
    sites = json.loads(get("https://supercharge.info/service/supercharge/allSites"))
    out = []
    for x in sites:
        addr = x.get("address") or {}
        gps = x.get("gps") or {}
        if (x.get("status") or "").upper() != "OPEN":
            continue
        if (addr.get("region") or "").lower() != "europe":
            continue
        lat, lon = gps.get("latitude"), gps.get("longitude")
        if lat is None or lon is None:
            continue
        out.append([round(lat, 5), round(lon, 5), x.get("name") or "",
                    x.get("stallCount") or 0, x.get("powerKilowatt") or 0,
                    1 if x.get("otherEVs") else 0,
                    (addr.get("street") or "")[:60], (addr.get("city") or "")[:40],
                    1 if x.get("solarCanopy") else 0, 1 if x.get("battery") else 0])
    print(f"Superchargeurs : {len(out)} sites ouverts en Europe")
    return {"updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "count": len(out), "items": out}


# Réseaux de recharge rapide connus (France + Suisse), repérés dans OpenStreetMap
NETWORKS = [
    ("Ionity", r"ionity"), ("Fastned", r"fastned"), ("Electra", r"electra"), ("Atlante", r"atlante"),
    ("Allego", r"allego"), ("TotalEnergies", r"total"), ("Engie Vianeo", r"vianeo|engie"), ("Izivia", r"izivia"),
    ("Power Dot", r"power ?dot"), ("Zunder", r"zunder"), ("Shell Recharge", r"shell"), ("bp pulse", r"bp ?pulse|aral pulse"),
    ("Lidl", r"lidl"), ("Electrify/EnBW", r"enbw"), ("Engie Belgique", r"engie electrabel"), ("GOFAST", r"gofast"), ("Move", r"^move|move mobility"), ("evpass", r"evpass"), ("Swisscharge", r"swisscharge"),
    ("Leclerc", r"leclerc"), ("Carrefour", r"carrefour"),
]
OVERPASS = ["https://overpass-api.de/api/interpreter", "https://overpass.kumi.systems/api/interpreter"]


def build_chargers():
    import re as _re
    rx = "|".join(r for _, r in NETWORKS).replace("^", "")
    q = f"""[out:json][timeout:300];
(area["ISO3166-1"="BE"][admin_level=2];area["ISO3166-1"="LU"][admin_level=2];area["ISO3166-1"="CH"][admin_level=2];)->.a;
(
  nwr["amenity"="charging_station"]["network"~"{rx}",i](area.a);
  nwr["amenity"="charging_station"]["operator"~"{rx}",i](area.a);
  nwr["amenity"="charging_station"]["brand"~"{rx}",i](area.a);
);
out center tags;"""
    data = None
    for url in OVERPASS:
        try:
            req = urllib.request.Request(url, data=("data=" + urllib.parse.quote(q)).encode(), headers={"User-Agent": "zones-app-data/1.0"})
            with urllib.request.urlopen(req, timeout=330) as r:
                data = json.loads(r.read())
            break
        except Exception as e:  # noqa: BLE001
            print(f"Bornes : échec {url} ({e})")
    if not data:
        raise RuntimeError("Overpass indisponible")
    out, seen = [], set()
    for el in data.get("elements", []):
        t = el.get("tags", {})
        lat = el.get("lat") or (el.get("center") or {}).get("lat")
        lon = el.get("lon") or (el.get("center") or {}).get("lon")
        if lat is None or lon is None:
            continue
        hay = " ".join([t.get("network", ""), t.get("operator", ""), t.get("brand", "")]).lower()
        if "tesla" in hay:
            continue  # déjà couverts par la couche Superchargeurs
        net = next((n for n, r in NETWORKS if _re.search(r, hay)), None)
        if not net:
            continue
        key = (round(lat, 4), round(lon, 4), net)
        if key in seen:
            continue
        seen.add(key)
        cap = t.get("capacity", "")
        kw = ""
        for k, v in t.items():
            if k.endswith(":output") and "kw" in v.lower():
                m = _re.search(r"([0-9]+(?:[.,][0-9]+)?)", v)
                if m:
                    kw = max(kw or 0, float(m.group(1).replace(",", ".")))
        out.append([round(lat, 5), round(lon, 5), net, (t.get("name") or "")[:60], int(cap) if str(cap).isdigit() else 0, int(kw) if kw else 0])
    print(f"Bornes : {len(out)} stations de {len(set(o[2] for o in out))} réseaux")
    return {"updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "count": len(out), "items": out}


# ---------- Base nationale française des bornes (IRVE, données publiques) ----------
IRVE_DATASETS = ["fichier-consolide-des-bornes-de-recharge-pour-vehicules-electriques",
                 "base-nationale-des-irve-data-gouv-infrastructures-de-recharge-pour-vehicules-electriques-donnees-statiques"]


def network_of(*names):
    import re as _re
    hay = " ".join(n or "" for n in names).lower()
    if "tesla" in hay:
        return None
    for n, r in NETWORKS:
        if _re.search(r, hay):
            return n
    return "Autres bornes"


def irve_csv_url():
    for slug in IRVE_DATASETS:
        try:
            meta = json.loads(get(f"https://www.data.gouv.fr/api/1/datasets/{slug}/"))
        except Exception as e:  # noqa: BLE001
            print(f"IRVE : jeu {slug} indisponible ({e})")
            continue
        res = [r for r in meta.get("resources", []) if (r.get("format") or "").lower() == "csv"]
        res.sort(key=lambda r: (("consolid" in (r.get("title") or "").lower()), r.get("last_modified") or ""), reverse=True)
        if res:
            print(f"IRVE : {res[0].get('title')} ({res[0].get('last_modified')})")
            return res[0]["url"]
    raise RuntimeError("Fichier IRVE introuvable")


def build_irve():
    import re as _re
    raw = get(irve_csv_url())
    text = raw.decode("utf-8-sig", errors="replace")
    rows = csv.DictReader(io.StringIO(text), delimiter=";" if text[:3000].count(";") > text[:3000].count(",") else ",")
    st = {}
    for r in rows:
        sid = (r.get("id_station_itinerance") or r.get("id_station_local") or "").strip()
        lat, lon = to_float(r.get("consolidated_latitude")), to_float(r.get("consolidated_longitude"))
        if lat is None or lon is None:
            m = _re.findall(r"-?[0-9]+(?:\.[0-9]+)?", r.get("coordonneesXY") or "")
            if len(m) >= 2:
                lon, lat = float(m[0]), float(m[1])
        if lat is None or lon is None or not (41 <= lat <= 52 and -6 <= lon <= 10):
            continue  # France métropolitaine
        key = sid or f"{round(lat, 4)},{round(lon, 4)}"
        p = to_float(r.get("puissance_nominale")) or 0
        if p > 1000:
            p = p / 1000.0  # certaines bornes sont déclarées en W
        plugs = set()
        for col, lab in (("prise_type_combo_ccs", "CCS"), ("prise_type_2", "Type 2"), ("prise_type_chademo", "CHAdeMO"), ("prise_type_ef", "Domestique")):
            if (r.get(col) or "").strip().lower() in ("true", "1", "oui", "vrai"):
                plugs.add(lab)
        s0 = st.get(key)
        if not s0:
            net = network_of(r.get("nom_enseigne"), r.get("nom_operateur"), r.get("nom_amenageur"))
            if not net:
                continue
            s0 = st[key] = {
                "lat": round(lat, 5), "lon": round(lon, 5), "net": net,
                "name": (r.get("nom_station") or "")[:60], "brand": (r.get("nom_enseigne") or r.get("nom_operateur") or "")[:40],
                "addr": (r.get("adresse_station") or "")[:90], "kw": 0, "pdc": 0, "plugs": set(),
                "price": (r.get("tarification") or "").strip()[:140],
                "free": (r.get("gratuit") or "").strip().lower() in ("true", "1", "oui", "vrai"),
                "hours": (r.get("horaires") or "").strip()[:40], "access": (r.get("condition_acces") or "").strip()[:40],
                "cb": (r.get("paiement_cb") or "").strip().lower() in ("true", "1", "oui", "vrai"),
            }
        s0["kw"] = max(s0["kw"], p)
        s0["pdc"] += 1
        s0["plugs"] |= plugs
        if not s0["price"] and r.get("tarification"):
            s0["price"] = r.get("tarification").strip()[:140]
    # Tuiles de 1° × 1° pour ne charger que la zone affichée
    tiles = {}
    for s0 in st.values():
        k = f"{int(s0['lat'] // 1)}_{int(s0['lon'] // 1)}"
        tiles.setdefault(k, []).append([s0["lat"], s0["lon"], s0["net"], s0["name"], s0["brand"], s0["addr"], int(round(s0["kw"])), s0["pdc"],
                                        ",".join(sorted(s0["plugs"])), s0["price"], 1 if s0["free"] else 0, s0["hours"], s0["access"], 1 if s0["cb"] else 0])
    os.makedirs("data/irve", exist_ok=True)
    for f in os.listdir("data/irve"):
        os.remove(os.path.join("data/irve", f))
    for k, items in tiles.items():
        with open(f"data/irve/{k}.json", "w") as fh:
            json.dump(items, fh, separators=(",", ":"), ensure_ascii=False)
    nets = {}
    for s0 in st.values():
        nets[s0["net"]] = nets.get(s0["net"], 0) + 1
    with open("data/irve/index.json", "w") as fh:
        json.dump({"updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "stations": len(st), "tiles": sorted(tiles), "networks": nets}, fh, ensure_ascii=False)
    print(f"IRVE : {len(st)} stations, {len(tiles)} tuiles, réseaux : {sorted(nets.items(), key=lambda x: -x[1])[:12]}")


def main():
    os.makedirs("data", exist_ok=True)
    pts = build_points()
    with open("data/points.json", "w") as fh:
        json.dump(pts, fh, separators=(",", ":"))
    border = build_border()
    border["banned"] = build_banned()
    with open("data/france.json", "w") as fh:
        json.dump(border, fh, separators=(",", ":"))
    try:
        sc = build_superchargers()
        if sc["count"] > 500:
            with open("data/superchargers.json", "w") as fh:
                json.dump(sc, fh, separators=(",", ":"), ensure_ascii=False)
    except Exception as e:  # noqa: BLE001
        print(f"Superchargeurs : échec ({e}), fichier précédent conservé")
    try:
        ch = build_chargers()
        if ch["count"] > 200:
            with open("data/chargers.json", "w") as fh:
                json.dump(ch, fh, separators=(",", ":"), ensure_ascii=False)
    except Exception as e:  # noqa: BLE001
        print(f"Bornes : échec ({e}), fichier précédent conservé")
    try:
        build_irve()
    except Exception as e:  # noqa: BLE001
        print(f"IRVE : échec ({e}), fichiers précédents conservés")
    print(f"OK : {pts['count']} points")


if __name__ == "__main__":
    sys.exit(main())
