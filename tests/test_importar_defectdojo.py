"""Pruebas del importador de DefectDojo contra un servidor HTTP falso."""

import io
import json
import re
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

import importar_defectdojo as imp  # noqa: E402

TOKEN = "token-de-prueba-1234567890"


class ServidorFalso:
    """Simula los endpoints de la API v2 que usa el importador."""

    def __init__(self):
        self.peticiones = []
        self.fallos_red = 0  # respuestas 503 antes de responder bien
        self.codigo_reimport = 201
        servidor = self

        class Manejador(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _responder(self, codigo, datos):
                cuerpo = json.dumps(datos).encode()
                self.send_response(codigo)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)

            def _registrar(self):
                largo = int(self.headers.get("Content-Length") or 0)
                cuerpo = self.rfile.read(largo) if largo else b""
                servidor.peticiones.append(
                    {"metodo": self.command, "ruta": self.path, "auth": self.headers.get("Authorization"), "cuerpo": cuerpo}
                )
                return cuerpo

            def do_GET(self):
                self._registrar()
                if self.path.startswith("/api/v2/findings/"):
                    self._responder(200, {"count": 3, "results": []})
                elif "/files/" in self.path:
                    adjuntos = [p for p in servidor.peticiones if p["metodo"] == "POST" and p["ruta"].endswith("/files/")]
                    self._responder(200, {"engagement_id": 9, "files": [{"id": i, "title": f"a{i}"} for i, _ in enumerate(adjuntos)]})
                else:
                    self._responder(200, {"count": 0, "results": []})

            def do_POST(self):
                cuerpo = self._registrar()
                if self.path == "/api/v2/reimport-scan/":
                    if servidor.fallos_red > 0:
                        servidor.fallos_red -= 1
                        self._responder(503, {"detail": "no disponible"})
                        return
                    if servidor.codigo_reimport >= 400:
                        self._responder(servidor.codigo_reimport, {"detail": "scan_type inválido"})
                        return
                    n = sum(1 for p in servidor.peticiones if p["ruta"] == "/api/v2/reimport-scan/")
                    self._responder(201, {"test_id": 100 + n, "engagement_id": 7, "product_id": 3, "statistics": {"after": {}}})
                elif self.path == "/api/v2/product_types/":
                    self._responder(201, {"id": 1})
                elif self.path == "/api/v2/products/":
                    self._responder(201, {"id": 3})
                elif self.path == "/api/v2/engagements/":
                    self._responder(201, {"id": 9, **json.loads(cuerpo)})
                elif self.path.endswith("/files/"):
                    self._responder(201, {"id": 1})
                else:
                    self._responder(404, {})

            def do_PATCH(self):
                self._registrar()
                self._responder(200, {"id": 7})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Manejador)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.hilo = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.hilo.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def campos_multipart(cuerpo: bytes) -> dict:
    return {m.group(1): m.group(2) for m in re.finditer(rb'name="([^"]+)"\r\n\r\n([^\r]*)\r\n', cuerpo)}


class ImportadorTest(unittest.TestCase):
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
        self.entorno = {
            "DEFECTDOJO_URL": self.servidor.url,
            "DEFECTDOJO_API_KEY": TOKEN,
            "GITHUB_RUN_ID": "123456",
            "GITHUB_SHA": "abcdef1234567890",
            "GITHUB_REF_NAME": "main",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "FidelRada/devsecops-proyecto-final-g10",
            "DEFECTDOJO_ESPERA_BASE": "0",
        }
        self.espera = mock.patch.object(imp, "ESPERA_BASE", 0)
        self.espera.start()

    def tearDown(self):
        self.espera.stop()
        self.servidor.__exit__()
        self.tmp.cleanup()

    def ejecutar(self, *argumentos):
        with mock.patch.dict("os.environ", self.entorno, clear=False), redirect_stdout(io.StringIO()) as salida:
            rc = imp.main(list(argumentos))
        return rc, salida.getvalue()

    def reimports(self):
        return [p for p in self.servidor.peticiones if p["ruta"] == "/api/v2/reimport-scan/"]

    def test_orden_scan_type_y_test_title(self):
        rc, _ = self.ejecutar("pipeline", "--reports", str(self.reports))
        self.assertEqual(rc, 0)
        enviados = [(c[b"scan_type"], c[b"test_title"]) for c in map(lambda p: campos_multipart(p["cuerpo"]), self.reimports())]
        self.assertEqual(
            enviados,
            [
                (b"Semgrep JSON Report", b"SAST - Semgrep"),
                (b"Trivy Scan", b"SCA - Trivy SBOM"),
                (b"Trivy Scan", b"Image Checker - Trivy"),
                (b"Conftest Scan", b"PaC - Conftest"),
            ],
        )

    def test_campos_de_contexto(self):
        self.ejecutar("pipeline", "--reports", str(self.reports))
        c = campos_multipart(self.reimports()[0]["cuerpo"])
        self.assertEqual(c[b"product_type_name"], b"Proyecto Final G10")
        self.assertEqual(c[b"product_name"], b"spring-boot-webapi-secure")
        self.assertEqual(c[b"engagement_name"], b"Pipeline CI/CD (main)")
        self.assertEqual(c[b"auto_create_context"], b"true")
        self.assertEqual(c[b"close_old_findings"], b"true")
        self.assertEqual(c[b"deduplication_execution_mode"], b"sync")
        self.assertEqual(c[b"build_id"], b"123456")
        self.assertEqual(c[b"commit_hash"], b"abcdef1234567890")
        self.assertEqual(c[b"branch_tag"], b"main")
        self.assertEqual(c[b"version"], b"abcdef1")
        self.assertEqual(c[b"source_code_management_uri"], b"https://github.com/FidelRada/devsecops-proyecto-final-g10")

    def test_patch_del_engagement(self):
        self.ejecutar("pipeline", "--reports", str(self.reports))
        patch = [p for p in self.servidor.peticiones if p["metodo"] == "PATCH"]
        self.assertEqual(len(patch), 1)
        self.assertEqual(patch[0]["ruta"], "/api/v2/engagements/7/")
        datos = json.loads(patch[0]["cuerpo"])
        self.assertEqual(datos["commit_hash"], "abcdef1234567890")
        self.assertEqual(datos["build_id"], "123456")

    def test_token_en_cabecera_y_no_en_la_salida(self):
        rc, salida = self.ejecutar("pipeline", "--reports", str(self.reports))
        self.assertEqual(rc, 0)
        self.assertTrue(all(p["auth"] == f"Token {TOKEN}" for p in self.servidor.peticiones))
        self.assertNotIn(TOKEN, salida)
        resumen = (self.reports / "defectdojo-123456.json").read_text(encoding="utf-8")
        self.assertNotIn(TOKEN, resumen)
        self.assertEqual(len(json.loads(resumen)["importaciones"]), 4)
        self.assertNotIn(TOKEN, repr(imp.Configuracion.desde_entorno(self.entorno)))

    def test_http_400_termina_con_error(self):
        self.servidor.codigo_reimport = 400
        rc, salida = self.ejecutar("pipeline", "--reports", str(self.reports))
        self.assertEqual(rc, 1)
        self.assertIn("HTTP 400", salida)
        self.assertEqual(len(self.reimports()), 1)  # sin reintentos ante un 4xx

    def test_reporte_faltante(self):
        (self.reports / "trivy-image.json").unlink()
        rc, salida = self.ejecutar("pipeline", "--reports", str(self.reports))
        self.assertEqual(rc, 2)
        self.assertIn("trivy-image.json", salida)
        self.assertEqual(self.reimports(), [])  # se valida todo antes de importar

    def test_reintento_acotado_ante_5xx(self):
        self.servidor.fallos_red = 1
        rc, _ = self.ejecutar("pipeline", "--reports", str(self.reports))
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.reimports()), 5)  # 1 fallo + 4 correctos

    def test_reintento_se_agota(self):
        self.servidor.fallos_red = 10
        rc, salida = self.ejecutar("pipeline", "--reports", str(self.reports))
        self.assertEqual(rc, 1)
        self.assertEqual(len(self.reimports()), imp.INTENTOS)
        self.assertIn("HTTP 503", salida)

    def test_error_de_red_acotado(self):
        self.entorno["DEFECTDOJO_URL"] = "http://127.0.0.1:9"  # puerto cerrado
        rc, salida = self.ejecutar("pipeline", "--reports", str(self.reports))
        self.assertEqual(rc, 1)
        self.assertIn("error de red", salida)

    def test_falta_api_key(self):
        self.entorno["DEFECTDOJO_API_KEY"] = ""
        rc, salida = self.ejecutar("pipeline", "--reports", str(self.reports))
        self.assertEqual(rc, 2)
        self.assertIn("DEFECTDOJO_API_KEY", salida)

    def test_modelo_de_amenazas(self):
        pdf = Path(self.tmp.name, "modelo.pdf")
        pdf.write_bytes(b"%PDF-1.4 prueba")
        modelo = Path(self.tmp.name, "modelo.json")
        modelo.write_text("{}", encoding="utf-8")
        rc, salida = self.ejecutar("modelo-amenazas", str(pdf), str(modelo))
        self.assertEqual(rc, 0)
        creado = [p for p in self.servidor.peticiones if p["ruta"] == "/api/v2/engagements/" and p["metodo"] == "POST"]
        datos = json.loads(creado[0]["cuerpo"])
        self.assertTrue(datos["threat_model"])
        self.assertEqual(datos["engagement_type"], "Interactive")
        self.assertEqual(datos["status"], "Completed")
        adjuntos = [p for p in self.servidor.peticiones if p["ruta"] == "/api/v2/engagements/9/files/" and p["metodo"] == "POST"]
        self.assertEqual(len(adjuntos), 2)
        self.assertEqual(len(json.loads(salida[salida.index("{"):])["archivos"]), 2)


if __name__ == "__main__":
    unittest.main()
