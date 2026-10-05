"""Casos límite y negativos del gate, del validador de Conftest y del importador de DefectDojo."""

import io
import json
import shutil
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
DATOS = Path(__file__).resolve().parent / "datos"
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import gate  # noqa: E402
import importar_defectdojo as imp  # noqa: E402
import validar_conftest as vc  # noqa: E402
from test_importar_defectdojo import TOKEN, ServidorFalso, campos_multipart  # noqa: E402

LIMPIOS = {
    "semgrep.json": "semgrep_limpio.json",
    "trivy-sca.json": "trivy_limpio.json",
    "trivy-image.json": "trivy_limpio.json",
    "conftest.json": "conftest_aprobado.json",
}


def trivy(*vulnerabilidades) -> str:
    return json.dumps(
        {"SchemaVersion": 2, "Results": [{"Target": "Java", "Vulnerabilities": list(vulnerabilidades)}]}
    )


def vuln(severidad: str, corregida=None, vid="CVE-2099-1000") -> dict:
    v = {"VulnerabilityID": vid, "PkgName": "lib", "InstalledVersion": "1.0", "Severity": severidad}
    if corregida is not None:
        v["FixedVersion"] = corregida
    return v


def semgrep(*severidades, errores=None) -> str:
    resultados = [
        {"check_id": f"regla-{n}", "path": "A.java", "start": {"line": n + 1}, "extra": {"severity": s}}
        for n, s in enumerate(severidades)
    ]
    return json.dumps({"version": "1.179.0", "results": resultados, "errors": errores or []})


# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------


class GateCasosLimiteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reports = Path(self.tmp.name, "reports")
        self.reports.mkdir()
        for destino, origen in LIMPIOS.items():
            shutil.copy(DATOS / origen, self.reports / destino)
        self.salida = self.reports / "gate.json"

    def tearDown(self):
        self.tmp.cleanup()

    def escribir(self, nombre: str, contenido) -> None:
        ruta = self.reports / nombre
        if isinstance(contenido, bytes):
            ruta.write_bytes(contenido)
        else:
            ruta.write_text(contenido, encoding="utf-8")

    def ejecutar(self) -> int:
        with redirect_stdout(io.StringIO()) as salida:
            rc = gate.main(["--reports", str(self.reports), "--output", str(self.salida), "--summary", ""])
        self.log = salida.getvalue()
        return rc

    def gate_json(self) -> dict:
        return json.loads(self.salida.read_text(encoding="utf-8"))

    # --- Semgrep -------------------------------------------------------------

    def test_semgrep_warning_e_info_no_bloquean(self):
        self.escribir("semgrep.json", semgrep("WARNING", "INFO"))
        self.assertEqual(self.ejecutar(), 0)
        conteo = self.gate_json()["conteos"]["SAST - Semgrep"]
        self.assertEqual((conteo["bloqueantes"], conteo["no_bloqueantes"]), (0, 2))

    def test_semgrep_error_en_minusculas_bloquea(self):
        self.escribir("semgrep.json", semgrep("error"))
        self.assertEqual(self.ejecutar(), 1)

    def test_semgrep_sin_severidad_no_bloquea(self):
        self.escribir("semgrep.json", json.dumps({"results": [{"check_id": "x", "path": "A.java"}], "errors": []}))
        self.assertEqual(self.ejecutar(), 0)

    def test_semgrep_error_tecnico_de_nivel_warn_no_es_fail_closed(self):
        self.escribir("semgrep.json", semgrep(errores=[{"level": "warn", "message": "regla lenta"}]))
        self.assertEqual(self.ejecutar(), 0)

    def test_semgrep_sin_results_es_fail_closed(self):
        self.escribir("semgrep.json", json.dumps({"errors": []}))
        self.assertEqual(self.ejecutar(), 2)

    # --- Trivy: severidades límite ---------------------------------------------

    def test_trivy_critical_con_correccion_bloquea(self):
        self.escribir("trivy-image.json", trivy(vuln("CRITICAL", "2.0")))
        self.assertEqual(self.ejecutar(), 1)

    def test_trivy_severidad_en_minusculas_bloquea(self):
        self.escribir("trivy-sca.json", trivy(vuln("high", "2.0")))
        self.assertEqual(self.ejecutar(), 1)

    def test_trivy_medium_low_unknown_con_correccion_no_bloquean(self):
        self.escribir("trivy-sca.json", trivy(vuln("MEDIUM", "2.0"), vuln("LOW", "2.0"), vuln("UNKNOWN", "2.0")))
        self.assertEqual(self.ejecutar(), 0)
        self.assertEqual(self.gate_json()["conteos"]["SCA - Trivy SBOM"]["no_bloqueantes"], 3)

    def test_trivy_high_sin_campo_fixedversion_no_bloquea(self):
        self.escribir("trivy-image.json", trivy(vuln("HIGH")))
        self.assertEqual(self.ejecutar(), 0)

    def test_trivy_critical_con_fixedversion_en_blanco_no_bloquea(self):
        self.escribir("trivy-image.json", trivy(vuln("CRITICAL", "   ")))
        self.assertEqual(self.ejecutar(), 0)

    def test_trivy_high_sin_correccion_no_bloquea_pero_se_cuenta(self):
        self.escribir("trivy-sca.json", trivy(vuln("HIGH", ""), vuln("CRITICAL", "")))
        self.assertEqual(self.ejecutar(), 0)
        conteo = self.gate_json()["conteos"]["SCA - Trivy SBOM"]
        self.assertEqual(conteo["por_severidad"], {"HIGH": 1, "CRITICAL": 1})

    def test_trivy_results_no_lista_es_fail_closed(self):
        self.escribir("trivy-sca.json", json.dumps({"SchemaVersion": 2, "Results": {"a": 1}}))
        self.assertEqual(self.ejecutar(), 2)

    # --- Conftest --------------------------------------------------------------

    def test_conftest_lista_vacia_es_fail_closed(self):
        self.escribir("conftest.json", "[]")
        self.assertEqual(self.ejecutar(), 2)

    def test_conftest_sin_filename_es_fail_closed(self):
        self.escribir("conftest.json", json.dumps([{"successes": 1}]))
        self.assertEqual(self.ejecutar(), 2)

    # --- Fail-closed ante cualquier reporte ilegible -----------------------------

    def test_reporte_no_utf8_es_fail_closed(self):
        self.escribir("conftest.json", b"\xff\xfe\x00")
        self.assertEqual(self.ejecutar(), 2)

    def test_gate_json_se_escribe_tambien_con_codigo_2(self):
        (self.reports / "semgrep.json").unlink()
        self.assertEqual(self.ejecutar(), 2)
        datos = self.gate_json()
        self.assertEqual(datos["decision"], "error")
        self.assertEqual(datos["errores"][0]["archivo"], "semgrep.json")

    def test_elementos_con_estructura_ajena_son_fail_closed(self):
        """Un elemento que no es objeto no debe romper el gate con una traza: código 2 y gate.json escrito."""
        casos = {
            "semgrep.json": [
                json.dumps({"results": ["x"], "errors": []}),
                json.dumps({"results": [], "errors": ["x"]}),
            ],
            "trivy-sca.json": [
                json.dumps({"SchemaVersion": 2, "Results": ["x"]}),
                json.dumps({"SchemaVersion": 2, "Results": [{"Target": "a", "Vulnerabilities": "x"}]}),
                json.dumps({"SchemaVersion": 2, "Results": [{"Target": "a", "Vulnerabilities": ["x"]}]}),
            ],
            "conftest.json": [
                json.dumps([{"filename": "Dockerfile", "failures": ["x"]}]),
                json.dumps([{"filename": "Dockerfile", "failures": {"msg": "x"}}]),
            ],
        }
        for archivo, contenidos in casos.items():
            for contenido in contenidos:
                with self.subTest(archivo=archivo, contenido=contenido):
                    shutil.copy(DATOS / LIMPIOS[archivo], self.reports / archivo)
                    self.salida.unlink(missing_ok=True)
                    self.escribir(archivo, contenido)
                    try:
                        rc = self.ejecutar()
                    except Exception as exc:  # noqa: BLE001
                        self.fail(f"el gate lanzó {type(exc).__name__}: {exc}")
                    self.assertEqual(rc, 2)
                    self.assertEqual(self.gate_json()["errores"][0]["archivo"], archivo)
            shutil.copy(DATOS / LIMPIOS[archivo], self.reports / archivo)

    # --- Salidas -------------------------------------------------------------------

    def test_markdown_trunca_bloqueantes(self):
        self.escribir("trivy-sca.json", trivy(*[vuln("HIGH", "2.0", f"CVE-2099-{n:04d}") for n in range(5)]))
        resultado = gate.evaluar(self.reports)
        texto = gate.a_markdown(resultado, max_filas=2)
        self.assertIn("3 más en gate.json", texto)
        self.assertNotIn("CVE-2099-0004", texto)


# ---------------------------------------------------------------------------
# Validador de Conftest
# ---------------------------------------------------------------------------


class ValidarConftestCasosLimiteTest(unittest.TestCase):
    APROBADO = [{"filename": "Dockerfile", "namespace": "main", "successes": 9}]

    def validar(self, texto_json, texto_err, rc):
        return vc.validar(texto_json, texto_err, rc)

    def test_rc1_stdout_vacio_y_stderr_rego_parse_error(self):
        err = "Error: running test: load: loading policies: /policy/dockerfile.rego:199: rego_parse_error: unexpected eof token\n"
        with self.assertRaises(vc.ErrorTecnico):
            self.validar("", err, 1)

    def test_rc1_stderr_rego_compile_error_sin_prefijo(self):
        with self.assertRaises(vc.ErrorTecnico):
            self.validar(json.dumps(self.APROBADO), "1 error occurred: rego_compile_error: x", 1)

    def test_rc1_stdout_y_stderr_vacios(self):
        with self.assertRaises(vc.ErrorTecnico):
            self.validar("", "", 1)

    def test_rc0_solo_warnings_es_valido(self):
        datos = [dict(self.APROBADO[0], warnings=[{"msg": "aviso"}])]
        self.assertEqual(self.validar(json.dumps(datos), "", 0), {"rc": 0, "failures": 0, "warnings": 1})

    def test_rc_de_senal_o_negativo(self):
        for rc in (-1, 137, 3):
            with self.subTest(rc=rc), self.assertRaises(vc.ErrorTecnico):
                self.validar(json.dumps(self.APROBADO), "", rc)

    def test_successes_booleano(self):
        with self.assertRaises(vc.ErrorTecnico):
            self.validar(json.dumps([dict(self.APROBADO[0], successes=True)]), "", 0)

    def test_failures_no_lista(self):
        with self.assertRaises(vc.ErrorTecnico):
            self.validar(json.dumps([dict(self.APROBADO[0], failures="x")]), "", 1)

    def test_reporte_objeto_en_lugar_de_lista(self):
        with self.assertRaises(vc.ErrorTecnico):
            self.validar(json.dumps(self.APROBADO[0]), "", 0)

    def test_numero_de_argumentos_incorrecto(self):
        with redirect_stdout(io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(vc.main(["a.json", "b.err"]), 2)


# ---------------------------------------------------------------------------
# Importador de DefectDojo
# ---------------------------------------------------------------------------


class ServidorHtml:
    """Responde 200 con HTML (p. ej., DEFECTDOJO_URL apunta a la página de login)."""

    def __init__(self):
        class Manejador(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _html(self):
                largo = int(self.headers.get("Content-Length") or 0)
                if largo:
                    self.rfile.read(largo)
                cuerpo = b"<html><body>login</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)

            do_GET = do_POST = do_PATCH = _html

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Manejador)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def cerrar(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ImportadorCasosLimiteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reports = Path(self.tmp.name)
        for destino, origen in {
            "semgrep.json": "semgrep_bloqueante.json",
            "trivy-sca.json": "trivy_bloqueante.json",
            "trivy-image.json": "trivy_sin_correccion.json",
            "conftest.json": "conftest_violacion.json",
        }.items():
            (self.reports / destino).write_bytes((DATOS / origen).read_bytes())
        self.servidor = ServidorFalso().__enter__()
        self.entorno = {"DEFECTDOJO_URL": self.servidor.url, "DEFECTDOJO_API_KEY": TOKEN, "GITHUB_RUN_ID": "77"}
        self.espera = mock.patch.object(imp, "ESPERA_BASE", 0)
        self.espera.start()

    def tearDown(self):
        self.espera.stop()
        self.servidor.__exit__()
        self.tmp.cleanup()

    def ejecutar(self, *argumentos):
        with mock.patch.dict("os.environ", self.entorno, clear=False), redirect_stdout(io.StringIO()) as salida:
            rc = imp.main(list(argumentos) or ["pipeline", "--reports", str(self.reports)])
        return rc, salida.getvalue()

    def reimports(self):
        return [p for p in self.servidor.peticiones if p["ruta"] == "/api/v2/reimport-scan/"]

    def test_orden_y_archivo_enviado_en_cada_reimport(self):
        rc, _ = self.ejecutar()
        self.assertEqual(rc, 0)
        nombres = [p["cuerpo"].split(b'filename="')[1].split(b'"')[0] for p in self.reimports()]
        self.assertEqual(nombres, [b"semgrep.json", b"trivy-sca.json", b"trivy-image.json", b"conftest.json"])
        tipos = [campos_multipart(p["cuerpo"])[b"scan_type"] for p in self.reimports()]
        self.assertEqual(tipos, [b"Semgrep JSON Report", b"Trivy Scan", b"Trivy Scan", b"Conftest Scan"])

    def test_reporte_vacio_o_invalido_no_importa_nada(self):
        for contenido in ("", "   \n", "{no es json"):
            with self.subTest(contenido=contenido):
                self.servidor.peticiones.clear()
                (self.reports / "conftest.json").write_text(contenido, encoding="utf-8")
                rc, salida = self.ejecutar()
                self.assertEqual(rc, 2)
                self.assertIn("conftest.json", salida)
                self.assertEqual(self.reimports(), [])

    def test_falta_url(self):
        self.entorno["DEFECTDOJO_URL"] = ""
        rc, salida = self.ejecutar()
        self.assertEqual(rc, 2)
        self.assertIn("DEFECTDOJO_URL", salida)

    def test_token_no_aparece_en_ninguna_salida_de_error(self):
        casos = {
            "http_400": lambda: setattr(self.servidor, "codigo_reimport", 400),
            "5xx_agotado": lambda: setattr(self.servidor, "fallos_red", 10),
            "red": lambda: self.entorno.update(DEFECTDOJO_URL="http://127.0.0.1:9"),
        }
        for nombre, preparar in casos.items():
            with self.subTest(caso=nombre):
                url = self.entorno["DEFECTDOJO_URL"]
                preparar()
                rc, salida = self.ejecutar()
                self.assertEqual(rc, 1)
                self.assertNotIn(TOKEN, salida)
                self.servidor.codigo_reimport, self.servidor.fallos_red = 201, 0
                self.entorno["DEFECTDOJO_URL"] = url

    def test_reintentos_con_espera_exponencial(self):
        self.servidor.fallos_red = 2
        with mock.patch.object(imp.time, "sleep") as dormir:
            cliente = imp.ClienteDefectDojo(imp.Configuracion.desde_entorno(self.entorno), espera_base=1)
            with redirect_stdout(io.StringIO()):
                cliente.reimportar(imp.reportes_del_pipeline(self.reports)[0])
        self.assertEqual([c.args[0] for c in dormir.call_args_list], [1, 2])
        self.assertEqual(len(self.reimports()), 3)

    def test_respuesta_no_json_termina_con_error_controlado(self):
        """Si DEFECTDOJO_URL apunta a algo que responde HTML, el importador debe salir con 1, sin traza."""
        html = ServidorHtml()
        self.addCleanup(html.cerrar)
        self.entorno["DEFECTDOJO_URL"] = html.url
        try:
            rc, salida = self.ejecutar()
        except Exception as exc:  # noqa: BLE001
            self.fail(f"el importador lanzó {type(exc).__name__}: {exc}")
        self.assertEqual(rc, 1)
        self.assertNotIn(TOKEN, salida)

    def test_reporte_no_utf8_es_error_de_entrada(self):
        (self.reports / "semgrep.json").write_bytes(b"\xff\xfe\x00")
        try:
            rc, _ = self.ejecutar()
        except Exception as exc:  # noqa: BLE001
            self.fail(f"el importador lanzó {type(exc).__name__}: {exc}")
        self.assertEqual(rc, 2)
        self.assertEqual(self.reimports(), [])


if __name__ == "__main__":
    unittest.main()
