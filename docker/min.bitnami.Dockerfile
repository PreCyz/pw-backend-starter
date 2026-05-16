FROM docker.io/bitnami/java-min:latest AS builder

# Przełączamy na roota tylko na chwilę, aby móc swobodnie operować w katalogu /builder
USER 0
WORKDIR /builder

# Kopiowanie i ekstrakcja Spring Boot Layered JAR
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} app.jar
RUN java -Djarmode=tools -jar app.jar extract --layers --destination extracted

FROM docker.io/bitnami/java-min:25

# Konfiguracja katalogów aplikacji i cache AOT
ENV AOT_DIR=/cache
ENV AOT_CACHE=${AOT_DIR}/app.aot
WORKDIR /application

# Przełączamy na root, aby utworzyć katalogi i nadać uprawnienia dla użytkownika Bitnami (1001)
USER 0
RUN mkdir -p ${AOT_DIR} /application && chown -R 1001:1001 ${AOT_DIR} /application

# Kopiowanie warstw aplikacji (z zachowaniem uprawnień dla użytkownika 1001)
COPY --from=builder --chown=1001:1001 /builder/extracted/dependencies/ ./
COPY --from=builder --chown=1001:1001 /builder/extracted/spring-boot-loader/ ./
COPY --from=builder --chown=1001:1001 /builder/extracted/snapshot-dependencies/ ./
COPY --from=builder --chown=1001:1001 /builder/extracted/application/ ./

# --- Faza Treningowa CDS/AOT ---
# Wracamy do bezpiecznego użytkownika Bitnami, aby wygenerować cache
USER 1001

ENV SERVER_PORT=8080
ENV MANAGEMENT_SERVER_PORT=8070
ENV SERVER_SERVLET_CONTEXT_PATH="/"
ENV SPRING_PROFILES_ACTIVE=mysql,batch,aot-warm-up
ENV MYSQL_HOSTNAME=host.docker.internal

# Generowanie cache AOT podczas budowania obrazu
RUN java -XX:AOTCacheOutput=$AOT_CACHE -jar app.jar

# --- Faza Uruchomieniowa ---
CMD ["/bin/sh", "-c", "java -Xlog:aot -XX:AOTCache=\"$AOT_CACHE\" -Dspring.profiles.active=mysql,batch,first-request -jar app.jar"]