FROM container-registry.oracle.com/java/openjdk:25-oraclelinux9 AS runtime-build

ARG MODULES=java.base,java.compiler,java.desktop,java.instrument,java.net.http,java.prefs,java.rmi,java.scripting,java.security.jgss,java.sql.rowset,jdk.jfr,jdk.management,jdk.management.agent,jdk.management.jfr,jdk.jcmd,jdk.net,jdk.unsupported

RUN $JAVA_HOME/bin/jlink \
	--add-modules ${MODULES} \
	--no-man-pages \
	--no-header-files \
    --compress=zip-9 \
	--output /javaruntime

FROM container-registry.oracle.com/os/oraclelinux:9-slim

ENV JAVA_HOME=/usr/java/openjdk-25
ENV PATH=$JAVA_HOME/bin:$PATH

COPY --from=runtime-build /javaruntime $JAVA_HOME

ARG JAR_FILE=target/*.jar
ARG AOT_DIR=cache

COPY ${JAR_FILE} app.jar

RUN mkdir ${AOT_DIR} && chmod 755 ${AOT_DIR}

ENV SERVER_PORT=8080
ENV MANAGEMENT_SERVER_PORT=8070
ENV SERVER_SERVLET_CONTEXT_PATH="/"
ENV	SPRING_PROFILES_ACTIVE=mysql,batch,aot-warm-up
ENV	MYSQL_HOSTNAME=host.docker.internal
ENV	AOT_CACHE=/$AOT_DIR/app.aot

# Continue with training run and assembly phase
RUN #java -XX:AOTCacheOutput=$AOT_CACHE -Dspring.context.exit=onRefresh -jar app.jar
RUN java -XX:AOTCacheOutput=$AOT_CACHE -jar app.jar

RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser

ENV	SPRING_PROFILES_ACTIVE=mysql,batch

# Deployment run
CMD ["/bin/sh", "-c", "java -Xlog:aot -XX:AOTCache=\"$AOT_CACHE\" -jar app.jar"]