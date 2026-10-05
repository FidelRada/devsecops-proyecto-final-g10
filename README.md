# Pipeline DevSecOps CI/CD con DefectDojo – Grupo 10

Proyecto final del Módulo 5 (Seguridad en DevOps), UAGRM – FICCT. Docente: MSc. José Pablo Villazón Valdez.

**Grupo 10:** Bautista Condori Anderzon, Grichukin Méndez Richard, Rada Rojas Andrés Fidel y Vargas Ríos Bebi.

Este repositorio parte de [`pablovillazon/spring-boot-webapi-secure`](https://github.com/pablovillazon/spring-boot-webapi-secure) (con su historial) y le agrega:

- un pipeline de **CI en GitHub Actions** con un step por análisis de seguridad y todos los reportes en JSON;
- un **quality gate** que decide con el contenido de los reportes;
- un **CD local** con un runner self-hosted y Docker Compose;
- la **importación automática** de los reportes en una instancia propia de **DefectDojo**;
- el **modelo de amenazas** del trabajo 1 en [`docs/threat-model/`](docs/threat-model/README.md).

> **Advertencia:** la aplicación es deliberadamente vulnerable. Ejecutarla solo en `localhost` o en una red de laboratorio aislada.

## Cómo funciona el pipeline

El workflow [`.github/workflows/devsecops.yml`](.github/workflows/devsecops.yml) se ejecuta en cada `push` a `main`, en cada pull request hacia `main` y a mano (`workflow_dispatch`). Tiene tres jobs:

```text
ci (GitHub, ubuntu-latest)
 ├─ Compilar y probar ............ mvn -B clean verify
 ├─ Pruebas de scripts ........... python3 -m unittest
 ├─ SAST - Semgrep ............... reports/semgrep.json
 ├─ SCA - SBOM CycloneDX ......... reports/bom.json
 ├─ SCA - Trivy SBOM ............. reports/trivy-sca.json
 ├─ Construir imagen ............. g10-webapi:<commit>
 ├─ Image Checker - Trivy ........ reports/trivy-image.json
 ├─ PaC - Conftest (pruebas de la política)
 ├─ PaC - Conftest (Dockerfile) .. reports/conftest.json
 ├─ Publicar reportes ............ artifact reportes-devsecops
 ├─ Quality gate ................. reports/gate.json (artifact gate)
 └─ Publicar imagen aprobada ..... artifact imagen-webapi (solo si el gate aprueba)
defectdojo (runner local; push a main o manual; corre aunque el gate falle)
 └─ Importar en DefectDojo ....... reimport-scan de los 4 reportes
cd-local (runner local; solo si ci y defectdojo terminan bien)
 ├─ Cargar imagen y comprobar que es la escaneada
 ├─ Desplegar con Docker Compose . 127.0.0.1:8085
 └─ Smoke test ................... GET /actuator/health
```

En los pull requests solo corre `ci`: los jobs locales aparecen como *skipped*. No hay análisis dinámico (DAST).

### Herramientas y reportes JSON

| Análisis | Herramienta (fijada por digest) | Parámetro JSON | Reporte | Parser en DefectDojo |
|---|---|---|---|---|
| SAST | Semgrep 1.179.0 (`p/java`, `p/owasp-top-ten` y `.semgrep.yml`) | `--json --output` (Semgrep no tiene `--format`) | `semgrep.json` | Semgrep JSON Report |
| SCA | CycloneDX Maven 2.9.3 + Trivy 0.74.0 | `outputFormat=json` (pom) y `--format json --output` | `bom.json`, `trivy-sca.json` | Trivy Scan |
| Image Checker | Trivy 0.74.0 | `--format json --output` | `trivy-image.json` | Trivy Scan |
| Policy as Code | Conftest v0.71.0 + `policy/dockerfile.rego` | `--output json` | `conftest.json` | Conftest Scan |

### Quality gate

[`scripts/gate.py`](scripts/gate.py) lee los cuatro reportes y termina con:

- **1 (bloqueado)** si hay un resultado de Semgrep `ERROR` (o `CRITICAL`/`HIGH`), una vulnerabilidad de Trivy `HIGH`/`CRITICAL` **con versión corregida**, o una violación `deny` de Conftest;
- **2 (fail-closed)** si un reporte falta, está vacío, no es JSON, tiene una estructura inesperada, Trivy no analizó ningún paquete (`Results` vacío) o Semgrep informó errores técnicos;
- **0 (aprobado)** en otro caso. Los `WARNING`, las vulnerabilidades sin corrección y los avisos `warn` se informan, pero no bloquean.

El resultado queda en `gate.json` y en el resumen del run. Conftest devuelve 1 tanto con violaciones como ante un error de sintaxis Rego, así que [`scripts/validar_conftest.py`](scripts/validar_conftest.py) revisa el código, stderr y la estructura del JSON antes de que decida el gate.

### Políticas del Dockerfile

[`policy/dockerfile.rego`](policy/dockerfile.rego) (Rego v1) **bloquea**: etapa final sin `USER` o con root; `FROM` sin tag o con `latest`; imagen final sin digest `@sha256:`; imagen final que no es JRE; falta de `HEALTHCHECK`; `ADD` de una URL remota; secretos en `ENV`/`ARG`. **Avisa**: `HEALTHCHECK` con `curl` en una imagen Alpine (no lo trae) y `COPY --from` sin `--chown`. Las pruebas están en `policy/dockerfile_test.rego`:

```bash
docker run --rm -v "$PWD:/project" -w /project openpolicyagent/conftest:v0.71.0 verify --policy policy
```

## Reproducir los análisis en local

```bash
mkdir -p reports
mvn -B clean verify
python3 -m unittest discover -s tests -v

docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/src" -w /src semgrep/semgrep:1.179.0 \
  semgrep scan --metrics=off --config p/java --config p/owasp-top-ten --config .semgrep.yml \
  --json --output reports/semgrep.json src/main/java

mvn -B -DskipTests org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom && cp target/bom.json reports/bom.json
docker run --rm -v "$PWD:/w" -v trivy-cache:/root/.cache/trivy -w /w aquasec/trivy:0.74.0 \
  sbom --format json --output reports/trivy-sca.json reports/bom.json

docker build -t g10-webapi:local .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:/w" -v trivy-cache:/root/.cache/trivy -w /w \
  aquasec/trivy:0.74.0 image --image-src docker --format json --output reports/trivy-image.json g10-webapi:local

rc=0; docker run --rm -v "$PWD:/project" -w /project openpolicyagent/conftest:v0.71.0 \
  test Dockerfile --parser dockerfile --policy policy --output json > reports/conftest.json 2> conftest.err || rc=$?
python3 scripts/validar_conftest.py reports/conftest.json conftest.err "$rc"

python3 scripts/gate.py --reports reports --output reports/gate.json
```

## DefectDojo local

Instancia propia de DefectDojo 3.3.300 con Docker Compose, publicada solo en `127.0.0.1:8080`.

```bash
git clone --depth 1 --branch 3.3.300 https://github.com/DefectDojo/django-DefectDojo.git defectdojo
cd defectdojo
```

1. Crear `.env.local` (permisos 600, **nunca** en Git) con valores aleatorios: `DJANGO_VERSION=3.3.300`, `NGINX_VERSION=3.3.300`, `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY`, `DD_ADMIN_PASSWORD`, `DD_DATABASE_PASSWORD` y `DD_DATABASE_URL` coherente. Por ejemplo, un valor: `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`.
2. Crear `docker-compose.override.yml` para escuchar solo en local y fijar la contraseña del administrador:

   ```yaml
   services:
     nginx:
       ports: !override
         - "127.0.0.1:8080:8080"
     initializer:
       environment:
         DD_ADMIN_PASSWORD: ${DD_ADMIN_PASSWORD}
   ```

3. Levantarla sin construir imágenes y esperar a que el `initializer` termine con código 0:

   ```bash
   docker compose --env-file .env.local pull
   docker compose --env-file .env.local up -d --no-build
   docker compose --env-file .env.local ps -a
   ```

4. Entrar en http://127.0.0.1:8080 con `admin` y la contraseña de `.env.local`. La API key del usuario se obtiene con `POST /api/v2/api-token-auth/` y se guarda en `.env.local` sin mostrarla.
5. Activar la deduplicación, que viene desactivada en una instalación nueva: *Configuration → System Settings → Deduplicate findings*, o `PATCH /api/v2/system_settings/1/` con `{"enable_deduplication": true}`.

Organización en DefectDojo:

- Product Type **Proyecto Final G10** → Product **spring-boot-webapi-secure**.
- Engagement CI/CD **Pipeline CI/CD (main)** con un Test por herramienta (*SAST - Semgrep*, *SCA - Trivy SBOM*, *Image Checker - Trivy*, *PaC - Conftest*). Cada push a `main` los reimporta: los hallazgos corregidos pasan a *Mitigated*. El Engagement guarda el run, el commit y la rama.
- Engagement **Modelado de amenazas – Caso 5 Banca Móvil** con el PDF y el JSON del modelo adjuntos:

  ```bash
  DEFECTDOJO_URL=http://127.0.0.1:8080 DEFECTDOJO_API_KEY=... python3 scripts/importar_defectdojo.py modelo-amenazas \
    docs/threat-model/Reporte_ThreatDragon_Caso5_Grupo10.pdf docs/threat-model/Grupo10_Caso5_BancaMovil.json
  ```

SCA se importa antes que la imagen: DefectDojo marca como *Duplicate* en el Test de imagen las CVE de librerías Java que ya reportó el SBOM, de modo que cada vulnerabilidad se gestiona una sola vez.

## Runner self-hosted (CD local)

Los jobs `defectdojo` y `cd-local` corren en la PC del grupo con un runner de GitHub Actions instalado con el usuario normal (sin `sudo` ni servicio del sistema):

```bash
mkdir runner && cd runner
curl -fsSLO https://github.com/actions/runner/releases/download/v2.337.0/actions-runner-linux-x64-2.337.0.tar.gz
# comprobar el SHA-256 publicado en la página del release
tar xzf actions-runner-linux-x64-2.337.0.tar.gz
./config.sh --url https://github.com/FidelRada/devsecops-proyecto-final-g10 --token <token de registro> \
  --name g10-pc --labels g10-local --unattended
./run.sh   # solo mientras se ejecuta el pipeline; detenerlo al terminar
```

Si la ruta del runner tiene espacios, la carpeta de trabajo (`workFolder` en `.runner`, o `--work` en `config.sh`) debe estar en una ruta **sin espacios**, por ejemplo `/home/<usuario>/g10-runner-work`: el runner pasa a `bash` la ruta del script del step sin comillas y un espacio la corta.

Seguridad del runner (el repositorio es público):

- el repositorio exige aprobación para los workflows de **todos** los colaboradores externos y nunca se aprueba un run de un fork;
- el secreto `DEFECTDOJO_API_KEY` existe solo en el entorno `cd-local`, que únicamente acepta la rama `main`;
- `./run.sh` se lanza solo durante la ejecución del pipeline (no como servicio);
- el `GITHUB_TOKEN` es de solo lectura y DefectDojo y la aplicación escuchan solo en `127.0.0.1`;
- los archivos de registro del runner (`.credentials`, `.credentials_rsaparams`, `.runner`) tienen permisos 600.

**Riesgo residual:** el usuario que ejecuta el runner pertenece al grupo `docker`, porque los jobs usan Docker. Eso equivale a tener privilegios de root en la PC: un workflow malicioso que llegara a ejecutarse en el runner podría tomar el control del equipo. Por eso los controles anteriores impiden que código de terceros llegue al runner (aprobación de forks, entorno restringido a `main`, protección de `main` con PR obligatorio y runner apagado fuera de las ejecuciones). Al terminar el proyecto, el runner se elimina con `./config.sh remove`.

El secreto lo crea el dueño del repositorio, leyendo el valor desde `.env.local` sin mostrarlo:

```bash
gh secret set DEFECTDOJO_API_KEY --env cd-local --repo FidelRada/devsecops-proyecto-final-g10 \
  < <(grep '^DD_API_KEY=' defectdojo/.env.local | cut -d= -f2-)
```

Las variables opcionales de la aplicación desplegada (usuarios y hashes) van en un archivo fuera del repositorio cuya ruta se indica en `APP_ENV_FILE` (por ejemplo, en el `.env` del runner).

## Aplicación base

API Spring Boot 3.5 (Java 21, Maven, H2 en memoria) del laboratorio, con vulnerabilidades intencionales.

```bash
mvn clean verify
mvn spring-boot:run   # http://localhost:8080
```

Endpoints:

```text
GET  /api/products/search?name=Laptop
POST /api/comments/preview
GET  /api/admin/users/1
POST /api/auth/login
```
