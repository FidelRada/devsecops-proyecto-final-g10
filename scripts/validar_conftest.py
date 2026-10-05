#!/usr/bin/env python3
"""Valida que la ejecución de Conftest terminó bien antes de pasar el reporte al gate.

Conftest devuelve 1 tanto cuando encuentra violaciones como cuando la política tiene
un error de sintaxis Rego (en ese caso, stdout queda vacío). El código de salida no
basta para distinguirlos, así que este script revisa también stderr y la estructura
del JSON.

Uso:
    python3 scripts/validar_conftest.py reports/conftest.json conftest.err <rc>

Códigos de salida:
    0  la ejecución es válida (con o sin violaciones; las decide el gate)
    2  error técnico: código inesperado, error en stderr o JSON con otra estructura
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

EXIT_VALIDO = 0
EXIT_ERROR_TECNICO = 2

MARCAS_DE_ERROR = ("Error:", "rego_parse_error", "rego_compile_error", "rego_type_error")


class ErrorTecnico(Exception):
    """La ejecución de Conftest no produjo un resultado confiable."""


def validar(texto_json: str, texto_err: str, rc: int, archivo: str = "Dockerfile") -> dict:
    """Devuelve un resumen si la ejecución es válida; si no, lanza ErrorTecnico."""
    if rc not in (0, 1):
        raise ErrorTecnico(f"Conftest terminó con el código {rc} (se esperaba 0 o 1)")

    for marca in MARCAS_DE_ERROR:
        if marca in texto_err:
            raise ErrorTecnico(f"stderr de Conftest contiene '{marca}'")

    if not texto_json.strip():
        raise ErrorTecnico("el reporte JSON está vacío")
    try:
        datos = json.loads(texto_json)
    except json.JSONDecodeError as exc:
        raise ErrorTecnico(f"el reporte no es JSON válido: {exc}") from exc

    if not isinstance(datos, list) or not datos:
        raise ErrorTecnico("el reporte debe ser una lista no vacía")

    total_failures = 0
    total_warnings = 0
    for item in datos:
        if not isinstance(item, dict):
            raise ErrorTecnico("cada resultado debe ser un objeto")
        if item.get("filename") != archivo:
            raise ErrorTecnico(f"resultado con filename {item.get('filename')!r} (se esperaba {archivo!r})")
        successes = item.get("successes")
        if isinstance(successes, bool) or not isinstance(successes, int):
            raise ErrorTecnico("falta 'successes' numérico")
        failures = item.get("failures") or []
        warnings = item.get("warnings") or []
        if not isinstance(failures, list) or not isinstance(warnings, list):
            raise ErrorTecnico("'failures' y 'warnings' deben ser listas")
        total_failures += len(failures)
        total_warnings += len(warnings)

    if rc == 1 and total_failures == 0:
        raise ErrorTecnico("Conftest devolvió 1 pero el reporte no tiene 'failures'")
    if rc == 0 and total_failures > 0:
        raise ErrorTecnico("Conftest devolvió 0 pero el reporte tiene 'failures'")

    return {"rc": rc, "failures": total_failures, "warnings": total_warnings}


def _leer(ruta: str) -> str:
    try:
        return Path(ruta).read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3:
        print("uso: validar_conftest.py <reporte.json> <stderr.txt> <rc>", file=sys.stderr)
        return EXIT_ERROR_TECNICO
    ruta_json, ruta_err, rc_texto = argv
    try:
        rc = int(rc_texto)
    except ValueError:
        print(f"::error::Código de salida de Conftest inválido: {rc_texto!r}")
        return EXIT_ERROR_TECNICO

    texto_err = _leer(ruta_err)
    try:
        resumen = validar(_leer(ruta_json), texto_err, rc)
    except ErrorTecnico as exc:
        print(f"::error::Error técnico de Conftest: {exc}")
        if texto_err.strip():
            print("stderr de Conftest:")
            print(texto_err[:2000])
        return EXIT_ERROR_TECNICO

    print(
        f"Conftest válido: código {resumen['rc']}, {resumen['failures']} violaciones (deny) "
        f"y {resumen['warnings']} avisos (warn). La decisión la toma el quality gate."
    )
    return EXIT_VALIDO


if __name__ == "__main__":
    sys.exit(main())
