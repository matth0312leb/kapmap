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


def main():
    os.makedirs("data", exist_ok=True)
    pts = build_points()
    with open("data/points.json", "w") as fh:
        json.dump(pts, fh, separators=(",", ":"))
    border = build_border()
    with open("data/france.json", "w") as fh:
        json.dump(border, fh, separators=(",", ":"))
    print(f"OK : {pts['count']} points")


if __name__ == "__main__":
    sys.exit(main())
