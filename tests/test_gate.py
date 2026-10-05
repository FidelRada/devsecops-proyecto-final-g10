"""Pruebas del quality gate con reportes de ejemplo (tests/datos)."""

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
DATOS = Path(__file__).resolve().parent / "datos"
sys.path.insert(0, str(RAIZ / "scripts"))

import gate  # noqa: E402

LIMPIOS = {
    "semgrep.json": "semgrep_limpio.json",
    "trivy-sca.json": "trivy_limpio.json",
    "trivy-image.json": "trivy_limpio.json",
    "conftest.json": "conftest_aprobado.json",
}


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reports = Path(self.tmp.name, "reports")
        self.reports.mkdir()
        self.salida = self.reports / "gate.json"
        self.resumen = Path(self.tmp.name, "resumen.md")

    def tearDown(self):
        self.tmp.cleanup()

    def preparar(self, **reemplazos):
        """Copia los reportes limpios y reemplaza los indicados (None = no copiar)."""
        archivos = dict(LIMPIOS)
        for destino, origen in reemplazos.items():
            archivos[destino.replace("_", "-") + ".json"] = origen
        for destino, origen in archivos.items():
            if origen is not None:
                shutil.copy(DATOS / origen, self.reports / destino)

    def ejecutar(self) -> int:
        with redirect_stdout(io.StringIO()) as salida:
            rc = gate.main(["--reports", str(self.reports), "--output", str(self.salida), "--summary", str(self.resumen)])
        self.log = salida.getvalue()
        return rc

    def gate_json(self) -> dict:
        return json.loads(self.salida.read_text(encoding="utf-8"))

    # --- código 0 ----------------------------------------------------------

    def test_reportes_limpios_aprueban(self):
        self.preparar()
        self.assertEqual(self.ejecutar(), 0)
        self.assertEqual(self.gate_json()["decision"], "aprobado")

    def test_high_sin_correccion_no_bloquea(self):
        self.preparar(trivy_image="trivy_sin_correccion.json")
        self.assertEqual(self.ejecutar(), 0)
        conteo = self.gate_json()["conteos"]["Image Checker - Trivy"]
        self.assertEqual(conteo["bloqueantes"], 0)
        self.assertEqual(conteo["no_bloqueantes"], 1)

    def test_warnings_de_conftest_no_bloquean(self):
        datos = [{"filename": "Dockerfile", "successes": 9, "warnings": [{"msg": "aviso"}]}]
        self.preparar()
        (self.reports / "conftest.json").write_text(json.dumps(datos), encoding="utf-8")
        self.assertEqual(self.ejecutar(), 0)

    # --- código 1 ----------------------------------------------------------

    def test_semgrep_error_bloquea(self):
        self.preparar(semgrep="semgrep_bloqueante.json")
        self.assertEqual(self.ejecutar(), 1)
        bloqueantes = self.gate_json()["bloqueantes"]
        self.assertEqual(bloqueantes[0]["regla"], "lab-java-sql-concatenation")

    def test_trivy_sca_con_correccion_bloquea(self):
        self.preparar(trivy_sca="trivy_bloqueante.json")
        self.assertEqual(self.ejecutar(), 1)
        self.assertEqual(self.gate_json()["bloqueantes"][0]["regla"], "CVE-2022-42889")

    def test_trivy_imagen_con_correccion_bloquea(self):
        self.preparar(trivy_image="trivy_bloqueante.json")
        self.assertEqual(self.ejecutar(), 1)

    def test_conftest_failures_bloquea(self):
        self.preparar(conftest="conftest_violacion.json")
        self.assertEqual(self.ejecutar(), 1)
        self.assertEqual(self.gate_json()["decision"], "bloqueado")

    def test_semgrep_critical_o_high_bloquea(self):
        for severidad in ("CRITICAL", "HIGH"):
            with self.subTest(severidad=severidad):
                self.preparar()
                datos = json.loads((DATOS / "semgrep_bloqueante.json").read_text(encoding="utf-8"))
                datos["results"][0]["extra"]["severity"] = severidad
                (self.reports / "semgrep.json").write_text(json.dumps(datos), encoding="utf-8")
                self.assertEqual(self.ejecutar(), 1)

    # --- código 2 (fail-closed) ----------------------------------------------

    def test_trivy_sin_results_es_fail_closed(self):
        for contenido in ({"SchemaVersion": 2}, {"SchemaVersion": 2, "Results": []}):
            with self.subTest(contenido=contenido):
                self.preparar()
                (self.reports / "trivy-sca.json").write_text(json.dumps(contenido), encoding="utf-8")
                self.assertEqual(self.ejecutar(), 2)

    def test_reporte_faltante(self):
        for nombre in LIMPIOS:
            with self.subTest(reporte=nombre):
                for f in self.reports.iterdir():
                    f.unlink()
                self.preparar(**{nombre[:-5].replace("-", "_"): None})
                self.assertEqual(self.ejecutar(), 2)
                self.assertIn(nombre, self.log)

    def test_reporte_vacio(self):
        self.preparar()
        (self.reports / "trivy-sca.json").write_text("  \n", encoding="utf-8")
        self.assertEqual(self.ejecutar(), 2)
        self.assertEqual(self.gate_json()["errores"][0]["archivo"], "trivy-sca.json")

    def test_reporte_no_json(self):
        self.preparar()
        (self.reports / "semgrep.json").write_text("<html>", encoding="utf-8")
        self.assertEqual(self.ejecutar(), 2)

    def test_reporte_con_estructura_ajena(self):
        self.preparar()
        (self.reports / "trivy-image.json").write_text('{"otra": 1}', encoding="utf-8")
        self.assertEqual(self.ejecutar(), 2)

    def test_semgrep_con_error_tecnico(self):
        self.preparar(semgrep="semgrep_error_tecnico.json")
        self.assertEqual(self.ejecutar(), 2)

    def test_fail_closed_prevalece_sobre_bloqueantes(self):
        self.preparar(semgrep="semgrep_bloqueante.json", conftest=None)
        self.assertEqual(self.ejecutar(), 2)

    # --- salidas -------------------------------------------------------------

    def test_resumen_markdown(self):
        self.preparar(trivy_sca="trivy_bloqueante.json")
        self.ejecutar()
        texto = self.resumen.read_text(encoding="utf-8")
        self.assertIn("## Quality gate", texto)
        self.assertIn("CVE-2022-42889", texto)

    def test_datos_de_reportes_neutralizados(self):
        self.preparar(semgrep="semgrep_inyeccion.json")
        self.assertEqual(self.ejecutar(), 1)
        texto = self.resumen.read_text(encoding="utf-8") + self.log
        self.assertNotIn("::warning::", texto)
        self.assertNotIn("::error::x", texto)
        for linea in self.resumen.read_text(encoding="utf-8").splitlines():
            self.assertNotIn("inyectado", linea if not linea.startswith("|") else "")


if __name__ == "__main__":
    unittest.main()
