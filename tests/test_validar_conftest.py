"""Pruebas del validador de la salida de Conftest."""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import validar_conftest as vc  # noqa: E402

CON_VIOLACIONES = [
    {
        "filename": "Dockerfile",
        "namespace": "main",
        "successes": 7,
        "warnings": [{"msg": "aviso", "metadata": {"query": "data.main.warn"}}],
        "failures": [{"msg": "violación", "metadata": {"query": "data.main.deny"}}],
    }
]
APROBADO = [{"filename": "Dockerfile", "namespace": "main", "successes": 9}]
ERROR_PARSE = "Error: running test: load: loading policies: 1 error occurred: policy/x.rego:3: rego_parse_error: unexpected eof token\n"


class ValidarConftestTest(unittest.TestCase):
    def ejecutar(self, contenido_json: str, contenido_err: str, rc) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            ruta_json = Path(tmp, "conftest.json")
            ruta_err = Path(tmp, "conftest.err")
            ruta_json.write_text(contenido_json, encoding="utf-8")
            ruta_err.write_text(contenido_err, encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                return vc.main([str(ruta_json), str(ruta_err), str(rc)])

    def test_violacion_valida_rc1(self):
        self.assertEqual(self.ejecutar(json.dumps(CON_VIOLACIONES), "", 1), 0)

    def test_aprobado_rc0(self):
        self.assertEqual(self.ejecutar(json.dumps(APROBADO), "", 0), 0)

    def test_aprobado_con_failures_vacio(self):
        datos = [dict(APROBADO[0], failures=[])]
        self.assertEqual(self.ejecutar(json.dumps(datos), "", 0), 0)

    def test_error_de_sintaxis_rego(self):
        # Conftest devuelve 1 y stdout vacío: es un error técnico, no una violación.
        self.assertEqual(self.ejecutar("", ERROR_PARSE, 1), 2)

    def test_stderr_con_error_aunque_el_json_sea_valido(self):
        self.assertEqual(self.ejecutar(json.dumps(CON_VIOLACIONES), ERROR_PARSE, 1), 2)

    def test_json_sin_filename(self):
        datos = [{"successes": 1, "failures": [{"msg": "x"}]}]
        self.assertEqual(self.ejecutar(json.dumps(datos), "", 1), 2)

    def test_otro_archivo(self):
        datos = [dict(CON_VIOLACIONES[0], filename="otro.yaml")]
        self.assertEqual(self.ejecutar(json.dumps(datos), "", 1), 2)

    def test_rc1_sin_failures(self):
        self.assertEqual(self.ejecutar(json.dumps(APROBADO), "", 1), 2)

    def test_rc0_con_failures(self):
        self.assertEqual(self.ejecutar(json.dumps(CON_VIOLACIONES), "", 0), 2)

    def test_rc2(self):
        self.assertEqual(self.ejecutar(json.dumps(CON_VIOLACIONES), "", 2), 2)

    def test_lista_vacia(self):
        self.assertEqual(self.ejecutar("[]", "", 0), 2)

    def test_json_invalido(self):
        self.assertEqual(self.ejecutar("{no es json", "", 1), 2)

    def test_successes_no_numerico(self):
        datos = [dict(APROBADO[0], successes="9")]
        self.assertEqual(self.ejecutar(json.dumps(datos), "", 0), 2)

    def test_rc_no_entero(self):
        self.assertEqual(self.ejecutar(json.dumps(APROBADO), "", "x"), 2)

    def test_archivo_json_inexistente(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            rc = vc.main([str(Path(tmp, "no.json")), str(Path(tmp, "no.err")), "1"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
