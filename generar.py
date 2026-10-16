"""Genera el archivo de datos del tablero de entregas de Ransa.

Lo corre GitHub automáticamente cada pocos minutos (ver .github/workflows/actualizar.yml):
  1. Lee SimpliRoute con el token (secreto SR_TOKEN de GitHub: nunca aparece en el sitio ni en el código).
  2. Se queda solo con lo que usa el tablero (sin teléfonos, firmas ni el usuario/DPI de los pilotos).
  3. Lo comprime y lo CIFRA con la clave del equipo (secreto CLAVE). Sin la clave el archivo no se puede leer.
  4. Deja el archivo cifrado en site/datos.bin; el flujo de GitHub lo publica en la rama "datos".
Solo hace consultas (GET) a SimpliRoute.
"""
import gzip
import json
import os
import sys
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SR = "https://api.simpliroute.com/v1/"
TOKEN = os.environ.get("SR_TOKEN", "").strip()
CLAVE = os.environ.get("CLAVE", "").strip()
DIAS = int(os.environ.get("DIAS", "3"))  # hoy y los días anteriores que se publican
ITERACIONES = 250000                      # debe ser igual al de index.html
AQUI = os.path.dirname(os.path.abspath(__file__))
SALIDA = os.path.join(AQUI, "site")

VISITA = ("id", "route", "planned_date", "order", "title", "address", "reference", "status", "checkin_time", "checkout_time",
          "checkout_comment", "checkout_observation", "visit_type", "route_status", "is_route_completed", "driver", "vehicle")
RUTA = ("id", "status", "planned_date", "start_time", "end_time", "kilometers", "reference", "driver", "vehicle", "plan",
        "total_visits", "location_start_address")


def sr_get(path, params=None):
    for intento in range(3):
        r = requests.get(SR + path, params=params, headers={"Authorization": "Token " + TOKEN}, timeout=(10, 120))
        if r.status_code == 429 and intento < 2:
            time.sleep(5 * (intento + 1))
            continue
        break
    r.raise_for_status()
    d = r.json()
    if isinstance(d, dict) and isinstance(d.get("results"), list):
        salida, sig, n = list(d["results"]), d.get("next"), 0
        while sig and n < 60:
            r2 = requests.get(str(sig).replace("http://", "https://"), headers={"Authorization": "Token " + TOKEN}, timeout=(10, 120))
            r2.raise_for_status()
            d2 = r2.json()
            salida += d2.get("results", [])
            sig, n = d2.get("next"), n + 1
        return salida
    return d


def recorta(d, campos):
    return {k: d.get(k) for k in campos}


def escalares(d):
    salida = {}
    for k, v in d.items():
        if v is None or isinstance(v, (str, int, float, bool)):
            salida[k] = v
        elif isinstance(v, dict) and len(v) <= 8 and all(x is None or isinstance(x, (str, int, float, bool)) for x in v.values()):
            salida[k] = v
    return salida


def construir():
    hoy = datetime.now(ZoneInfo("America/Guatemala")).date()
    fechas = [(hoy - timedelta(days=i)).isoformat() for i in range(DIAS - 1, -1, -1)]
    visitas, rutas, planes = [], [], []
    for f in fechas:
        visitas += [recorta(v, VISITA) for v in sr_get("routes/visits/", {"planned_date": f})]
        rutas += [recorta(r, RUTA) for r in sr_get("routes/routes/", {"planned_date": f})]
        try:
            planes += [escalares(p) for p in sr_get("routes/plans/", {"planned_date": f})]
        except Exception:
            pass  # si SimpliRoute no deja leer los planes, el tablero funciona igual
    # De los pilotos solo el nombre: el usuario de SimpliRoute es el DPI y no se publica
    conductores = [{"id": d.get("id"), "name": d.get("name"), "first_name": d.get("first_name"), "last_name": d.get("last_name")}
                   for d in sr_get("accounts/drivers/")]
    vehiculos = [{"id": v.get("id"), "license_plate": v.get("license_plate"), "name": v.get("name")} for v in sr_get("routes/vehicles/")]
    return {"generado": datetime.now(ZoneInfo("UTC")).isoformat(), "fechas": fechas, "visitas": visitas, "rutas": rutas,
            "planes": planes, "conductores": conductores, "vehiculos": vehiculos}


def cifrar(datos, clave):
    crudo = gzip.compress(json.dumps(datos, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), 9)
    sal, iv = os.urandom(16), os.urandom(12)
    llave = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sal, iterations=ITERACIONES).derive(clave.encode("utf-8"))
    return sal + iv + AESGCM(llave).encrypt(iv, crudo, None)


def main():
    if not TOKEN or not CLAVE:
        sys.exit("Faltan los secretos SR_TOKEN y/o CLAVE en GitHub (Settings > Secrets and variables > Actions).")
    if len(CLAVE) < 10:
        sys.exit("La CLAVE es muy corta: usa al menos 10 caracteres, porque protege los datos.")
    datos = construir()
    os.makedirs(SALIDA, exist_ok=True)
    with open(os.path.join(SALIDA, "datos.bin"), "wb") as f:
        f.write(cifrar(datos, CLAVE))
    print(f"Listo: {len(datos['visitas'])} visitas y {len(datos['rutas'])} rutas de {', '.join(datos['fechas'])}.")


if __name__ == "__main__":
    main()
