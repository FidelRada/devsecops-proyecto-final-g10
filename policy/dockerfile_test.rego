# Pruebas de las políticas del Dockerfile: `conftest verify --policy policy`.
# Cada caso usa el `input` tal como lo entrega el parser dockerfile de Conftest.
package main

import rego.v1

# ---------------------------------------------------------------------------
# Dockerfile de referencia que cumple todas las reglas
# ---------------------------------------------------------------------------

desde_build := {"Cmd": "from", "Flags": [], "Stage": 0, "Value": ["maven:3.9.16-eclipse-temurin-21-alpine@sha256:308c", "AS", "builder"]}

paquete := {"Cmd": "run", "Flags": [], "Stage": 0, "Value": ["mvn package -DskipTests -B"]}

desde_final := {"Cmd": "from", "Flags": [], "Stage": 1, "Value": ["eclipse-temurin:21.0.12.1_1-jre-alpine-3.24@sha256:51ab"]}

usuario := {"Cmd": "user", "Flags": [], "Stage": 1, "Value": ["spring:spring"]}

copia := {"Cmd": "copy", "Flags": ["--from=builder", "--chown=spring:spring"], "Stage": 1, "Value": ["/app/target/*.jar", "app.jar"]}

salud := {"Cmd": "healthcheck", "Flags": ["--interval=30s"], "Stage": 1, "Value": ["CMD", "wget -qO- http://localhost:8080/actuator/health || exit 1"]}

valido := [desde_build, paquete, desde_final, usuario, copia, salud]

# Reemplaza la instrucción en la posición `n` del Dockerfile válido.
con(n, instruccion) := [x | some k, v in valido; x := elegir(k, n, v, instruccion)]

elegir(k, n, _, instruccion) := instruccion if k == n

elegir(k, n, v, _) := v if k != n

# Quita la instrucción en la posición `n`.
sin(n) := [v | some k, v in valido; k != n]

hay_deny(entrada, texto) if {
	resultado := deny with input as entrada
	some m in resultado
	contains(m, texto)
}

hay_warn(entrada, texto) if {
	resultado := warn with input as entrada
	some m in resultado
	contains(m, texto)
}

# ---------------------------------------------------------------------------
# Caso válido
# ---------------------------------------------------------------------------

test_dockerfile_valido_sin_deny if {
	resultado := deny with input as valido
	count(resultado) == 0
}

test_dockerfile_valido_sin_warn if {
	resultado := warn with input as valido
	count(resultado) == 0
}

# ---------------------------------------------------------------------------
# 1. USER
# ---------------------------------------------------------------------------

test_sin_user_falla if hay_deny(sin(3), "no declara USER")

test_user_root_falla if hay_deny(con(3, {"Cmd": "user", "Flags": [], "Stage": 1, "Value": ["root"]}), "root")

test_user_cero_falla if hay_deny(con(3, {"Cmd": "user", "Flags": [], "Stage": 1, "Value": ["0:0"]}), "root")

test_user_no_root_pasa if not hay_deny(valido, "USER")

# ---------------------------------------------------------------------------
# 2. Tag explícito y distinto de latest
# ---------------------------------------------------------------------------

test_from_sin_tag_falla if hay_deny(con(0, {"Cmd": "from", "Flags": [], "Stage": 0, "Value": ["maven", "AS", "builder"]}), "no tiene tag")

test_from_latest_falla if hay_deny(con(0, {"Cmd": "from", "Flags": [], "Stage": 0, "Value": ["maven:latest", "AS", "builder"]}), "latest")

test_from_con_tag_pasa if {
	not hay_deny(valido, "no tiene tag")
	not hay_deny(valido, "latest")
}

test_from_de_otra_etapa_no_es_imagen if {
	entrada := array.concat(valido, [{"Cmd": "from", "Flags": [], "Stage": 2, "Value": ["builder"]}])
	not hay_deny(entrada, "no tiene tag")
}

# ---------------------------------------------------------------------------
# 3. Digest en la etapa final
# ---------------------------------------------------------------------------

test_final_sin_digest_falla if hay_deny(con(2, {"Cmd": "from", "Flags": [], "Stage": 1, "Value": ["eclipse-temurin:21-jre-alpine"]}), "digest")

test_final_con_digest_pasa if not hay_deny(valido, "digest")

# ---------------------------------------------------------------------------
# 4. Imagen final JRE
# ---------------------------------------------------------------------------

test_final_jdk_falla if hay_deny(con(2, {"Cmd": "from", "Flags": [], "Stage": 1, "Value": ["eclipse-temurin:21-jdk-alpine@sha256:0bfc"]}), "no es un JRE")

test_final_jre_pasa if not hay_deny(valido, "no es un JRE")

# ---------------------------------------------------------------------------
# 5. HEALTHCHECK
# ---------------------------------------------------------------------------

test_sin_healthcheck_falla if hay_deny(sin(5), "HEALTHCHECK")

test_healthcheck_none_falla if hay_deny(con(5, {"Cmd": "healthcheck", "Flags": [], "Stage": 1, "Value": ["NONE"]}), "HEALTHCHECK")

test_con_healthcheck_pasa if not hay_deny(valido, "HEALTHCHECK")

# ---------------------------------------------------------------------------
# 6. ADD remoto
# ---------------------------------------------------------------------------

test_add_remoto_falla if {
	entrada := array.concat(valido, [{"Cmd": "add", "Flags": [], "Stage": 1, "Value": ["https://ejemplo.com/a.tgz", "/tmp/"]}])
	hay_deny(entrada, "ADD")
}

test_add_local_pasa if {
	entrada := array.concat(valido, [{"Cmd": "add", "Flags": [], "Stage": 1, "Value": ["config.tgz", "/tmp/"]}])
	not hay_deny(entrada, "ADD")
}

# ---------------------------------------------------------------------------
# 7. Secretos en ENV/ARG
# ---------------------------------------------------------------------------

test_env_con_secreto_falla if {
	entrada := array.concat(valido, [{"Cmd": "env", "Flags": [], "Stage": 1, "Value": ["DB_PASSWORD", "clave", "="]}])
	hay_deny(entrada, "DB_PASSWORD")
}

test_arg_con_secreto_falla if {
	entrada := array.concat(valido, [{"Cmd": "arg", "Flags": [], "Stage": 0, "Value": ["API_KEY=abc"]}])
	hay_deny(entrada, "API_KEY")
}

test_env_sin_secreto_pasa if {
	entrada := array.concat(valido, [{"Cmd": "env", "Flags": [], "Stage": 1, "Value": ["JAVA_OPTS", "-Xmx256m", "="]}])
	not hay_deny(entrada, "secreto")
}

test_arg_secreto_sin_valor_pasa if {
	entrada := array.concat(valido, [{"Cmd": "arg", "Flags": [], "Stage": 0, "Value": ["API_KEY"]}])
	not hay_deny(entrada, "secreto")
}

# ---------------------------------------------------------------------------
# Avisos
# ---------------------------------------------------------------------------

test_healthcheck_curl_en_alpine_avisa if {
	entrada := con(5, {"Cmd": "healthcheck", "Flags": [], "Stage": 1, "Value": ["CMD", "curl -f http://localhost:8080/actuator/health || exit 1"]})
	hay_warn(entrada, "curl")
}

test_healthcheck_wget_no_avisa if not hay_warn(valido, "curl")

test_copy_sin_chown_avisa if {
	entrada := con(4, {"Cmd": "copy", "Flags": ["--from=builder"], "Stage": 1, "Value": ["/app/target/*.jar", "app.jar"]})
	hay_warn(entrada, "--chown")
}

test_copy_con_chown_no_avisa if not hay_warn(valido, "--chown")
