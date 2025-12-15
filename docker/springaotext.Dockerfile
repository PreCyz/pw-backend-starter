FROM container-registry.oracle.com/java/openjdk:25-oraclelinux9 AS builder

ARG MODULES=java.base,java.compiler,java.desktop,java.instrument,java.net.http,java.prefs,java.rmi,java.scripting,java.security.jgss,java.sql.rowset,jdk.jfr,jdk.management,jdk.management.agent,jdk.management.jfr,jdk.jcmd,jdk.net,jdk.unsupported

RUN $JAVA_HOME/bin/jlink \
  --add-modules ${MODULES} \
  --no-man-pages \
  --no-header-files \
  --compress=zip-9 \
  --output /javaruntime

WORKDIR /builder
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} app.jar
RUN $JAVA_HOME/bin/java -Djarmode=tools -jar app.jar extract --layers --destination extracted

# Runtime image
FROM container-registry.oracle.com/os/oraclelinux:9-slim

ENV JAVA_HOME=/usr/java/openjdk-25
ENV PATH=$JAVA_HOME/bin:$PATH
ARG AOT_DIR=/cache

COPY --from=builder /javaruntime $JAVA_HOME

WORKDIR /application
COPY --from=builder /builder/extracted/dependencies/ ./
COPY --from=builder /builder/extracted/spring-boot-loader/ ./
COPY --from=builder /builder/extracted/snapshot-dependencies/ ./
COPY --from=builder /builder/extracted/application/ ./

# Non-root runtime
RUN groupadd -r appuser && useradd -r -g appuser appuser && chown -R appuser:appuser /application
USER appuser

ENV SERVER_PORT=8080
ENV MANAGEMENT_SERVER_PORT=8070
ENV SERVER_SERVLET_CONTEXT_PATH="/"
ENV	SPRING_PROFILES_ACTIVE=mysql,batch,first-request
ENV	MYSQL_HOSTNAME=host.docker.internal
ENV AOT_CACHE=${AOT_DIR}/spring-aot-app.aot

CMD ["/bin/sh", "-c", "java -Xlog:aot -XX:AOTCache=\"$AOT_CACHE\" -Dspring.aot.enabled=true -jar app.jar"]