# ---- Build stage ----
FROM maven:3.9.16-eclipse-temurin-21-alpine AS builder
WORKDIR /app

# Copy pom first (better layer caching)
COPY pom.xml .

# Download dependencies (cached unless pom changes)
RUN mvn dependency:go-offline -B

# Copy source and build
COPY src src
RUN mvn package -DskipTests -B

# ---- Runtime stage ----
FROM eclipse-temurin:21-jdk-alpine

# Security: run as non-root user
RUN addgroup -S spring && adduser -S -G spring spring
USER spring:spring

WORKDIR /app

# Copy only the fat jar
COPY --from=builder /app/target/*.jar app.jar

# Optional: expose actuator / app port
EXPOSE 8080

# Health check (adjust path if needed)
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]