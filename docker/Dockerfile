FROM eclipse-temurin:25-jdk-alpine AS builder
WORKDIR /builder
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} app.jar
RUN java -Djarmode=tools -jar app.jar extract --layers --destination app


FROM eclipse-temurin:25-jre-alpine
WORKDIR /app
COPY --from=builder builder/app/dependencies/ ./
COPY --from=builder builder/app/snapshot-dependencies/ ./
COPY --from=builder builder/app/spring-boot-loader/ ./
COPY --from=builder builder/app/application/ ./

ENV SERVER_PORT=8080
ENV MANAGEMENT_SERVER_PORT=8070
ENV SERVER_SERVLET_CONTEXT_PATH="/"
ENV	SPRING_PROFILES_ACTIVE=mysql,batch
ENV	MYSQL_HOSTNAME=host.docker.internal

EXPOSE 8080 8070

ENTRYPOINT ["java", "-jar", "/app/app.jar"]