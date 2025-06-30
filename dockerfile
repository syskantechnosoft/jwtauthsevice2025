# Stage 1: Build with Maven
FROM eclipse-temurin:21-jdk-jammy as builder

WORKDIR /workspace/app

# Cache dependencies separately
COPY pom.xml .
COPY mvnw .
COPY .mvn/ .mvn/
RUN ./mvnw dependency:go-offline -B

# Build application with layered JAR
COPY src src
RUN ./mvnw package -DskipTests && \
    mkdir -p target/extracted && \
    java -Djarmode=layertools -jar target/*.jar extract --destination target/extracted

# Stage 2: Production image
FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

# Create non-root user
RUN useradd -m appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appuser /app
USER appuser

# Copy extracted layers
COPY --from=builder /workspace/app/target/extracted/dependencies/ ./
COPY --from=builder /workspace/app/target/extracted/spring-boot-loader/ ./
COPY --from=builder /workspace/app/target/extracted/snapshot-dependencies/ ./
COPY --from=builder /workspace/app/target/extracted/application/ ./

# H2 database configuration
# ENV SPRING_DATASOURCE_URL=jdbc:h2:file:/app/data/mydb
ENV SPRING_DATASOURCE_URL=jdbc:h2:mem:testdb
ENV SPRING_DATASOURCE_DRIVER_CLASS_NAME=org.h2.Driver
ENV SPRING_DATASOURCE_USERNAME=sa
ENV SPRING_DATASOURCE_PASSWORD=
ENV SPRING_H2_CONSOLE_ENABLED=true
ENV SPRING_H2_CONSOLE_PATH=/h2-console

# Render-specific optimizations
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75 -Dfile.encoding=UTF-8"
ENV SPRING_PROFILES_ACTIVE=prod

EXPOSE 8085

ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} org.springframework.boot.loader.JarLauncher"]
