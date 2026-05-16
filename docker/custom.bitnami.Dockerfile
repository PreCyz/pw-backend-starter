FROM docker.io/bitnami/minideb:bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    tar \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/opt/openjdk-25
ENV PATH=$JAVA_HOME/bin:$PATH

RUN mkdir -p ${JAVA_HOME} \
    && curl -fL https://download.java.net/java/GA/jdk25.0.2/b1e0dfa218384cb9959bdcb897162d4e/10/GPL/openjdk-25.0.2_linux-x64_bin.tar.gz | tar -xzC ${JAVA_HOME} --strip-components=1

# Definicja modułów do jlink
ARG MODULES=java.base,java.compiler,java.desktop,java.instrument,java.net.http,java.prefs,java.rmi,java.scripting,java.security.jgss,java.sql.rowset,jdk.jfr,jdk.management,jdk.management.agent,jdk.management.jfr,jdk.jcmd,jdk.net,jdk.unsupported

# Budowanie odchudzonego runtime za pomocą jlink
RUN jlink \
    --add-modules ${MODULES} \
    --no-man-pages \
    --no-header-files \
    --compress=zip-9 \
    --output /javaruntime

WORKDIR /builder

# Kopiowanie i ekstrakcja Spring Boot Layered JAR
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} app.jar
RUN java -Djarmode=tools -jar app.jar extract --layers --destination extracted


# ==========================================
# Etap 2: Runtime (Budowanie cache AOT i uruchomienie)
# ==========================================
FROM docker.io/bitnami/minideb:bookworm

# Definicja zmiennych środowiskowych dla Javy
ENV JAVA_HOME=/opt/javaruntime
ENV PATH=$JAVA_HOME/bin:$PATH

# Kopiowanie customowego runtime z etapu builder
COPY --from=builder /javaruntime $JAVA_HOME

# Konfiguracja katalogów aplikacji i cache AOT
ENV AOT_DIR=/cache
ENV AOT_CACHE=${AOT_DIR}/app.aot
WORKDIR /application

# Bitnami standardowo używa użytkownika 1001. Tworzymy katalogi i nadajemy im uprawnienia dla tego UID.
RUN mkdir -p ${AOT_DIR} /application && chown -R 1001:1001 ${AOT_DIR} /application

# Kopiowanie warstw aplikacji (z zachowaniem uprawnień dla użytkownika 1001)
COPY --from=builder --chown=1001:1001 /builder/extracted/dependencies/ ./
COPY --from=builder --chown=1001:1001 /builder/extracted/spring-boot-loader/ ./
COPY --from=builder --chown=1001:1001 /builder/extracted/snapshot-dependencies/ ./
COPY --from=builder --chown=1001:1001 /builder/extracted/application/ ./

# --- Faza Treningowa CDS/AOT ---
# Przełączamy się na użytkownika Bitnami (1001), aby wygenerować cache z właściwymi uprawnieniami
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