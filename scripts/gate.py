#!/usr/bin/env python3
"""Quality gate del pipeline DevSecOps.

Decide si el pipeline aprueba leyendo el CONTENIDO de los reportes JSON, no el código
de salida de los escáneres. Es fail-closed: si un reporte requerido falta, está vacío
o no se puede interpretar, el gate falla.

Bloquean (código 1):
  - Semgrep:          resultados con extra.severity ERROR (o CRITICAL/HIGH).
  - Trivy (SCA/imagen): vulnerabilidades HIGH o CRITICAL con FixedVersion (hay corrección).
  - Conftest:         cualquier entrada en "failures" (reglas deny).
Se informan sin bloquear: Semgrep WARNING/INFO, Trivy HIGH/CRITICAL sin corrección,
MEDIUM/LOW/UNKNOWN y los "warnings" de Conftest.

Códigos de salida:
  0  aprobado
  1  hallazgos bloqueantes
  2  reporte faltante, vacío o ilegible, o Semgrep con errores técnicos (fail-closed)

Solo usa la biblioteca estándar de Python 3.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

EXIT_APROBADO = 0
EXIT_BLOQUEADO = 1
EXIT_FAIL_CLOSED = 2

SEVERIDADES_TRIVY_BLOQUEANTES = {"HIGH", "CRITICAL"}
# ERROR es la severidad máxima de las reglas actuales; CRITICAL y HIGH son las de las
# reglas con el esquema de severidades nuevo de Semgrep.
SEVERIDADES_SEMGREP_BLOQUEANTES = {"ERROR", "CRITICAL", "HIGH"}

# Reporte -> herramienta, en el orden en que se presentan.
REPORTES = {
    "semgrep.json": "SAST - Semgrep",
    "trivy-sca.json": "SCA - Trivy SBOM",
    "trivy-image.json": "Image Checker - Trivy",
    "conftest.json": "PaC - Conftest",
}


class ReporteInvalido(Exception):
    """El reporte existe pero no se puede interpretar."""


@dataclass
class Hallazgo:
    herramienta: str
    regla: str
    severidad: str
    ubicacion: str
    bloquea: bool
    detalle: str = ""


@dataclass
class Resultado:
    hallazgos: list = field(default_factory=list)
    errores: list = field(default_factory=list)  # (archivo, motivo)

    @property
    def bloqueantes(self) -> list:
        return [h for h in self.hallazgos if h.bloquea]

    def codigo(self) -> int:
        if self.errores:
            return EXIT_FAIL_CLOSED
        if self.bloqueantes:
            return EXIT_BLOQUEADO
        return EXIT_APROBADO

    def decision(self) -> str:
        return {EXIT_APROBADO: "aprobado", EXIT_BLOQUEADO: "bloqueado", EXIT_FAIL_CLOSED: "error"}[self.codigo()]


# ---------------------------------------------------------------------------
# Lectura de reportes
# ---------------------------------------------------------------------------


def leer_json(ruta: Path):
    if not ruta.is_file():
        raise ReporteInvalido("reporte faltante")
    try:
        texto = ruta.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReporteInvalido(f"no se pudo leer: {exc}") from exc
    if not texto.strip():
        raise ReporteInvalido("reporte vacío")
    try:
        return json.loads(texto)
    except json.JSONDecodeError as exc:
        raise ReporteInvalido(f"JSON inválido: {exc}") from exc


def evaluar_semgrep(datos, herramienta: str) -> list:
    if not isinstance(datos, dict) or not isinstance(datos.get("results"), list):
        raise ReporteInvalido("no es un reporte de Semgrep (falta 'results')")
    errores = [e for e in datos.get("errors") or [] if str((e or {}).get("level", "")).lower() == "error"]
    if errores:
        raise ReporteInvalido(f"Semgrep informó {len(errores)} errores técnicos de nivel 'error'")
    hallazgos = []
    for r in datos["results"]:
        extra = r.get("extra") or {}
        severidad = str(extra.get("severity", "INFO")).upper()
        linea = (r.get("start") or {}).get("line")
        hallazgos.append(
            Hallazgo(
                herramienta=herramienta,
                regla=str(r.get("check_id", "?")),
                severidad=severidad,
                ubicacion=f"{r.get('path', '?')}:{linea}" if linea else str(r.get("path", "?")),
                bloquea=severidad in SEVERIDADES_SEMGREP_BLOQUEANTES,
            )
        )
    return hallazgos


def evaluar_trivy(datos, herramienta: str) -> list:
    if not isinstance(datos, dict) or "SchemaVersion" not in datos:
        raise ReporteInvalido("no es un reporte de Trivy (falta 'SchemaVersion')")
    resultados = datos.get("Results")
    if not isinstance(resultados, list) or not resultados:
        # Trivy incluye en Results los paquetes analizados aunque no tengan vulnerabilidades:
        # una lista vacía o ausente indica que no se analizó nada (p. ej., un SBOM vacío).
        raise ReporteInvalido("'Results' vacío o ausente: no se analizó ningún paquete")
    hallazgos = []
    for res in resultados or []:
        objetivo = res.get("Target", "?")
        for v in res.get("Vulnerabilities") or []:
            severidad = str(v.get("Severity", "UNKNOWN")).upper()
            corregida = str(v.get("FixedVersion") or "").strip()
            hallazgos.append(
                Hallazgo(
                    herramienta=herramienta,
                    regla=str(v.get("VulnerabilityID", "?")),
                    severidad=severidad,
                    ubicacion=f"{v.get('PkgName', '?')}@{v.get('InstalledVersion', '')} ({objetivo})",
                    bloquea=severidad in SEVERIDADES_TRIVY_BLOQUEANTES and bool(corregida),
                    detalle=f"corregida en {corregida}" if corregida else "sin corrección",
                )
            )
    return hallazgos


def evaluar_conftest(datos, herramienta: str) -> list:
    if not isinstance(datos, list) or not datos:
        raise ReporteInvalido("no es un reporte de Conftest (se esperaba una lista no vacía)")
    hallazgos = []
    for item in datos:
        if not isinstance(item, dict) or "filename" not in item:
            raise ReporteInvalido("resultado de Conftest sin 'filename'")
        archivo = item["filename"]
        for f in item.get("failures") or []:
            hallazgos.append(Hallazgo(herramienta, "deny", "FAILURE", archivo, True, str(f.get("msg", ""))))
        for w in item.get("warnings") or []:
            hallazgos.append(Hallazgo(herramienta, "warn", "WARNING", archivo, False, str(w.get("msg", ""))))
    return hallazgos


EVALUADORES = {
    "semgrep.json": evaluar_semgrep,
    "trivy-sca.json": evaluar_trivy,
    "trivy-image.json": evaluar_trivy,
    "conftest.json": evaluar_conftest,
}


def evaluar(carpeta: Path) -> Resultado:
    resultado = Resultado()
    for archivo, herramienta in REPORTES.items():
        try:
            datos = leer_json(carpeta / archivo)
            resultado.hallazgos.extend(EVALUADORES[archivo](datos, herramienta))
        except ReporteInvalido as exc:
            resultado.errores.append((archivo, str(exc)))
        except (AttributeError, TypeError, KeyError, ValueError) as exc:
            resultado.errores.append((archivo, f"estructura inesperada: {type(exc).__name__}"))
    return resultado


# ---------------------------------------------------------------------------
# Salidas
# ---------------------------------------------------------------------------


def neutralizar(texto) -> str:
    """Evita que datos de los reportes se interpreten como comandos de workflow o rompan la tabla."""
    texto = str(texto).replace("\r", " ").replace("\n", " ")
    texto = texto.replace("::", ": :").replace("|", "\\|").replace("`", "'")
    return texto[:300]


def conteos(resultado: Resultado) -> dict:
    tabla = {h: {"bloqueantes": 0, "no_bloqueantes": 0, "por_severidad": {}} for h in REPORTES.values()}
    for h in resultado.hallazgos:
        t = tabla[h.herramienta]
        t["bloqueantes" if h.bloquea else "no_bloqueantes"] += 1
        t["por_severidad"][h.severidad] = t["por_severidad"].get(h.severidad, 0) + 1
    return tabla


def a_json(resultado: Resultado) -> dict:
    return {
        "decision": resultado.decision(),
        "codigo_salida": resultado.codigo(),
        "criterios": {
            "semgrep": "extra.severity ERROR, CRITICAL o HIGH",
            "trivy": "Severity HIGH o CRITICAL con FixedVersion",
            "conftest": "failures no vacío",
        },
        "conteos": conteos(resultado),
        "bloqueantes": [asdict(h) for h in resultado.bloqueantes],
        "errores": [{"archivo": a, "motivo": m} for a, m in resultado.errores],
    }


def a_markdown(resultado: Resultado, max_filas: int = 100) -> str:
    icono = {"aprobado": "✅", "bloqueado": "❌", "error": "⚠️"}[resultado.decision()]
    lineas = [
        "## Quality gate",
        "",
        f"**Decisión: {icono} {resultado.decision()}** (código de salida {resultado.codigo()})",
        "",
        "Bloquean: Semgrep `ERROR` (o `CRITICAL`/`HIGH`); Trivy `HIGH`/`CRITICAL` con versión corregida; Conftest `failures`.",
        "",
        "| Herramienta | Bloqueantes | No bloqueantes | Por severidad |",
        "|---|---:|---:|---|",
    ]
    for herramienta, c in conteos(resultado).items():
        sev = ", ".join(f"{k}: {v}" for k, v in sorted(c["por_severidad"].items())) or "—"
        lineas.append(f"| {herramienta} | {c['bloqueantes']} | {c['no_bloqueantes']} | {sev} |")
    lineas.append("")
    if resultado.errores:
        lineas += ["### Reportes con errores (fail-closed)", "", "| Archivo | Motivo |", "|---|---|"]
        lineas += [f"| {neutralizar(a)} | {neutralizar(m)} |" for a, m in resultado.errores]
        lineas.append("")
    bloqueantes = resultado.bloqueantes
    if bloqueantes:
        lineas += ["### Hallazgos bloqueantes", "", "| Herramienta | Regla / CVE | Severidad | Ubicación | Detalle |", "|---|---|---|---|---|"]
        for h in bloqueantes[:max_filas]:
            lineas.append(
                f"| {h.herramienta} | {neutralizar(h.regla)} | {neutralizar(h.severidad)} | "
                f"{neutralizar(h.ubicacion)} | {neutralizar(h.detalle)} |"
            )
        if len(bloqueantes) > max_filas:
            lineas.append(f"| … | {len(bloqueantes) - max_filas} más en gate.json | | | |")
        lineas.append("")
    return "\n".join(lineas) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Quality gate de los reportes JSON del pipeline (fail-closed).")
    parser.add_argument("--reports", required=True, help="carpeta con los reportes JSON")
    parser.add_argument("--output", required=True, help="ruta del gate.json que se escribe")
    parser.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"), help="archivo Markdown del resumen")
    args = parser.parse_args(argv)

    resultado = evaluar(Path(args.reports))

    salida = Path(args.output)
    salida.parent.mkdir(parents=True, exist_ok=True)
    salida.write_text(json.dumps(a_json(resultado), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(a_markdown(resultado))

    for archivo, motivo in resultado.errores:
        print(f"::error::Reporte {neutralizar(archivo)}: {neutralizar(motivo)}")
    for h in resultado.bloqueantes:
        print(f"Bloqueante [{h.herramienta}] {neutralizar(h.regla)} ({neutralizar(h.severidad)}) en {neutralizar(h.ubicacion)}")
    for herramienta, c in conteos(resultado).items():
        print(f"{herramienta}: {c['bloqueantes']} bloqueantes, {c['no_bloqueantes']} no bloqueantes")
    print(f"Quality gate: {resultado.decision()} (código {resultado.codigo()})")
    return resultado.codigo()


if __name__ == "__main__":
    sys.exit(main())
