# ---- Build stage ----
FROM maven:3.9.16-eclipse-temurin-21-alpine@sha256:308cba8b638ed7e4658cea3f8399066219466211c805f6d5728c3c9c7614661b AS builder
WORKDIR /app

# Copy pom first (better layer caching)
COPY pom.xml .

# Download dependencies (cached unless pom changes)
RUN mvn dependency:go-offline -B

# Copy source and build
COPY src src
RUN mvn package -DskipTests -B

# ---- Runtime stage ----
# JRE (sin herramientas de desarrollo) fijado por digest.
FROM eclipse-temurin:21.0.12.1_1-jre-alpine-3.24@sha256:51ab5e3302e7141ce665ca3ea85e8b5cd648eafbc3c0c90dd79d6537684e4555

# Security: run as non-root user
RUN addgroup -S spring && adduser -S -G spring spring
USER spring:spring

WORKDIR /app

# Copy only the fat jar, owned by the application user
COPY --from=builder --chown=spring:spring /app/target/*.jar app.jar

# Optional: expose actuator / app port
EXPOSE 8080

# Health check: la imagen Alpine trae wget, no curl
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD wget -qO- http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
