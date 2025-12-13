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


FROM container-registry.oracle.com/os/oraclelinux:9-slim

ENV JAVA_HOME=/usr/java/openjdk-25
ENV PATH=$JAVA_HOME/bin:$PATH
ENV AOT_DIR=/cache
RUN mkdir $AOT_DIR && chmod 777 $AOT_DIR

COPY --from=builder /javaruntime $JAVA_HOME

WORKDIR /application
COPY --from=builder /builder/extracted/dependencies/ ./
COPY --from=builder /builder/extracted/spring-boot-loader/ ./
COPY --from=builder /builder/extracted/snapshot-dependencies/ ./
COPY --from=builder /builder/extracted/application/ ./

ENV AOT_CACHE=/$AOT_DIR/spring-aot-app.aot
ENV SERVER_PORT=8080
ENV MANAGEMENT_SERVER_PORT=8070
ENV SERVER_SERVLET_CONTEXT_PATH="/"
ENV	SPRING_PROFILES_ACTIVE=mysql,batch,aot-warm-up
#ENV	SPRING_PROFILES_ACTIVE=mysql,batch
ENV	MYSQL_HOSTNAME=host.docker.internal

#CMD ["/bin/sh","-c", "java -Xlog:aot,exceptions=trace -XX:AOTCacheOutput=\"${AOT_CACHE}\" -Dspring.context.exit=onRefresh -jar app.jar"]
CMD ["/bin/sh","-c", "java -Xlog:aot -XX:AOTCacheOutput=\"${AOT_CACHE}\" -jar app.jar"]