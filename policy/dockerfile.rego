# Políticas del Dockerfile (Conftest, Rego v1).
#
# Con `conftest test Dockerfile --parser dockerfile`, `input` es la lista de
# instrucciones del Dockerfile. Cada instrucción tiene:
#   Cmd   -> instrucción en minúsculas ("from", "user", "copy", ...)
#   Value -> argumentos (en un FROM, la imagen es Value[0])
#   Flags -> opciones ("--from=builder", "--chown=...")
#   Stage -> número de etapa (0, 1, ...)
#
# `deny` bloquea (Conftest devuelve 1 y DefectDojo lo clasifica como High).
# `warn` solo avisa (DefectDojo lo clasifica como Medium).
package main

import rego.v1

# ---------------------------------------------------------------------------
# Datos auxiliares
# ---------------------------------------------------------------------------

etapa_final := max({i.Stage | some i in input})

instrucciones_finales contains i if {
	some i in input
	i.Stage == etapa_final
}

# Alias de etapas ("FROM ... AS builder"): un FROM que apunta a otra etapa no es una imagen.
alias_etapas contains lower(i.Value[2]) if {
	some i in input
	i.Cmd == "from"
	count(i.Value) >= 3
	lower(i.Value[1]) == "as"
}

imagenes_externas contains imagen if {
	some i in input
	i.Cmd == "from"
	imagen := i.Value[0]
	not lower(imagen) in alias_etapas
	lower(imagen) != "scratch"
}

imagen_final := i.Value[0] if {
	some i in instrucciones_finales
	i.Cmd == "from"
}

# Nombre sin digest y último segmento de la ruta (para no confundir "registro:5000/img").
nombre_sin_digest(imagen) := split(imagen, "@")[0]

ultimo_segmento(imagen) := s if {
	partes := split(nombre_sin_digest(imagen), "/")
	s := partes[count(partes) - 1]
}

tiene_tag(imagen) if contains(ultimo_segmento(imagen), ":")

tiene_digest(imagen) if contains(imagen, "@sha256:")

tag(imagen) := t if {
	partes := split(ultimo_segmento(imagen), ":")
	t := partes[count(partes) - 1]
}

usuario_root(valor) if {
	usuario := split(valor, ":")[0]
	usuario in {"root", "0"}
}

nombre_secreto(nombre) if regex.match(`(?i)(password|secret|token|api_?key)`, nombre)

# ENV NOMBRE=valor llega como tríos [nombre, valor, "="].
variables_env contains [nombre, valor] if {
	some i in input
	i.Cmd == "env"
	some k in numbers.range(0, count(i.Value) - 1)
	k % 3 == 0
	nombre := i.Value[k]
	valor := i.Value[k + 1]
}

# ARG NOMBRE=valor llega como una sola cadena.
variables_env contains [nombre, valor] if {
	some i in input
	i.Cmd == "arg"
	some texto in i.Value
	contains(texto, "=")
	nombre := split(texto, "=")[0]
	valor := substring(texto, count(nombre) + 1, -1)
}

# ---------------------------------------------------------------------------
# Reglas que bloquean
# ---------------------------------------------------------------------------

# 1. La etapa final debe ejecutarse con un usuario no root.
deny contains "La etapa final no declara USER: el contenedor se ejecutaría como root" if {
	not usuario_final_declarado
}

usuario_final_declarado if {
	some i in instrucciones_finales
	i.Cmd == "user"
}

deny contains msg if {
	some i in instrucciones_finales
	i.Cmd == "user"
	usuario_root(i.Value[0])
	msg := sprintf("La etapa final usa USER %s (root)", [i.Value[0]])
}

# 2. Toda imagen base debe tener un tag explícito distinto de latest.
deny contains msg if {
	some imagen in imagenes_externas
	not tiene_tag(imagen)
	not tiene_digest(imagen)
	msg := sprintf("La imagen %s no tiene tag ni digest (equivale a latest)", [imagen])
}

deny contains msg if {
	some imagen in imagenes_externas
	tiene_tag(imagen)
	tag(imagen) == "latest"
	msg := sprintf("La imagen %s usa el tag latest", [imagen])
}

# 3. La imagen base de la etapa final debe fijarse por digest.
deny contains msg if {
	some i in instrucciones_finales
	i.Cmd == "from"
	not tiene_digest(i.Value[0])
	msg := sprintf("La imagen final %s no está fijada por digest (@sha256:)", [i.Value[0]])
}

# 4. La imagen final debe ser un JRE, no un JDK completo.
deny contains msg if {
	not contains(lower(imagen_final), "jre")
	msg := sprintf("La imagen final %s no es un JRE: incluye herramientas de desarrollo innecesarias", [imagen_final])
}

# 5. Debe existir un HEALTHCHECK en la etapa final.
deny contains "La etapa final no define HEALTHCHECK" if {
	not healthcheck_final
}

healthcheck_final if {
	some i in instrucciones_finales
	i.Cmd == "healthcheck"
	upper(i.Value[0]) != "NONE"
}

# 6. ADD no debe descargar contenido remoto.
deny contains msg if {
	some i in input
	i.Cmd == "add"
	some origen in i.Value
	regex.match(`^(?i)https?://`, origen)
	msg := sprintf("ADD descarga contenido remoto sin verificar: %s", [origen])
}

# 7. ENV/ARG no deben contener secretos.
deny contains msg if {
	some par in variables_env
	nombre := par[0]
	nombre_secreto(nombre)
	par[1] != ""
	msg := sprintf("La variable %s parece un secreto escrito en el Dockerfile", [nombre])
}

# ---------------------------------------------------------------------------
# Avisos (no bloquean)
# ---------------------------------------------------------------------------

# Las imágenes Temurin Alpine no traen curl: el HEALTHCHECK fallaría en ejecución.
warn contains "El HEALTHCHECK usa curl, que no existe en la imagen Alpine final (usar wget)" if {
	contains(lower(imagen_final), "alpine")
	some i in instrucciones_finales
	i.Cmd == "healthcheck"
	some parte in i.Value
	regex.match(`(^|[\s"'\[])curl(\s|$)`, parte)
}

# Los archivos copiados desde otra etapa deben pertenecer al usuario de la aplicación.
warn contains msg if {
	some i in instrucciones_finales
	i.Cmd == "copy"
	some f in i.Flags
	startswith(f, "--from=")
	not tiene_chown(i)
	msg := sprintf("COPY %s sin --chown: los archivos quedan con dueño root", [f])
}

tiene_chown(i) if {
	some f in i.Flags
	startswith(f, "--chown=")
}
