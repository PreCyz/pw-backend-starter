# ETAP 1: Ekstrakcja warstw (może być pełny obraz)
#FROM bitnami/java:sha256-20d48cdfa121178e58ed35dd7f94b7ce9a4a4d7298dbe8835a08f3553558a792 AS builder
FROM bitnami/java:latest AS builder
WORKDIR /builder
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} app.jar
# Rozbijamy JAR na warstwy (Spring Boot 3.x+)
RUN java -Djarmode=layertools -jar app.jar extract --destination extracted

# ETAP 2: Obraz docelowy (wersja MIN)
FROM bitnami/java-min:latest

WORKDIR /application

# Kopiujemy warstwy z buildera
COPY --from=builder /builder/extracted/dependencies/ ./
COPY --from=builder /builder/extracted/spring-boot-loader/ ./
COPY --from=builder /builder/extracted/snapshot-dependencies/ ./
COPY --from=builder /builder/extracted/application/ ./

# Konfiguracja środowiska
ENV SERVER_PORT=8080 \
    MANAGEMENT_SERVER_PORT=8070 \
    SPRING_PROFILES_ACTIVE=mysql,batch \
    SERVER_SERVLET_CONTEXT_PATH="/" \
    MYSQL_HOSTNAME=host.docker.internal

# W Bitnami użytkownik 1001 już istnieje, po prostu go używamy
USER 1001

# Startujemy za pomocą Launchera, a nie bezpośrednio z JAR
ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]