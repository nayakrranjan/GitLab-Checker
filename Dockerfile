# Multi-stage build for GitLab Public Repository Risk Scanner
FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /workspace

# Copy Maven wrapper and POM for dependency resolution
COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN chmod +x ./mvnw

# Copy source code and static assets
COPY src src

# Package the application JAR (skip tests during container build)
RUN ./mvnw clean package -DskipTests

# Stage 2: Minimal, secure runtime container
FROM eclipse-temurin:21-jre-alpine

LABEL maintainer="Metron Security SDE Candidate"
LABEL description="GitLab Public Repository Risk Scanner"

# Create unprivileged user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy built JAR from builder stage
COPY --from=builder /workspace/target/*.jar app.jar
RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

ENV JAVA_OPTS="-Xms256m -Xmx512m -XX:+UseG1GC"
ENV GITLAB_BASE_URL="https://gitlab.com"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
