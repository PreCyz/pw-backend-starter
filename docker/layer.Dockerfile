FROM container-registry.oracle.com/java/openjdk:25-oraclelinux9 AS builder

ARG MODULES=java.base,java.compiler,java.desktop,java.instrument,java.net.http,java.prefs,java.rmi,java.scripting,java.security.jgss,java.sql.rowset,jdk.jfr,jdk.management,jdk.management.agent,jdk.management.jfr,jdk.jcmd,jdk.net,jdk.unsupported

RUN $JAVA_HOME/bin/jlink \
	--add-modules ${MODULES} \
	--no-man-pages \
	--no-header-files \
    --compress=zip-9 \
	--output /javaruntime

WORKDIR /builder
# This points to the built jar file in the target folder
# Adjust this to 'build/libs/*.jar' if you're using Gradle
ARG JAR_FILE=../target/*.jar
# Copy the jar file to the working directory and rename it to application.jar
COPY ${JAR_FILE} app.jar
# Extract the jar file using an efficient layout
RUN $JAVA_HOME/bin/java -Djarmode=tools -jar app.jar extract --layers --destination extracted

FROM container-registry.oracle.com/os/oraclelinux:9-slim

ENV JAVA_HOME /usr/java/openjdk-25
ENV PATH $JAVA_HOME/bin:$PATH
ENV AOT_DIR=/cache

COPY --from=builder /javaruntime $JAVA_HOME

WORKDIR /application
# Copy the extracted jar contents from the builder container into the working directory in the runtime container
# Every copy step creates a new docker layer
# This allows docker to only pull the changes it really needs
COPY --from=builder /builder/extracted/dependencies/ ./
COPY --from=builder /builder/extracted/spring-boot-loader/ ./
COPY --from=builder /builder/extracted/snapshot-dependencies/ ./
COPY --from=builder /builder/extracted/application/ ./

# Continue with training run and assembly phase
RUN mkdir ${AOT_DIR} && chmod 755 ${AOT_DIR} \
    && java -XX:AOTCacheOutput=${AOT_DIR}/app.aot -Dspring.context.exit=onRefresh -jar app.jar \
    && groupadd -r appuser && useradd -r -g appuser appuser

USER appuser

# Deployment run
CMD java -XX:AOTCache=${AOT_DIR}/app.aot -jar app.jar