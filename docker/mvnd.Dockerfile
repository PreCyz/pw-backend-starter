FROM alpine:latest AS fetcher
RUN apk add --no-cache curl
ARG MVND_VERSION=1.0.5
RUN curl -L https://github.com/apache/maven-mvnd/releases/download/${MVND_VERSION}/maven-mvnd-${MVND_VERSION}-linux-amd64.tar.gz -o mvnd.tar.gz \
    && tar -xzf mvnd.tar.gz

FROM eclipse-temurin:25-jdk-noble
COPY --from=fetcher /maven-mvnd-* /opt/mvnd
ENV PATH="/opt/mvnd/bin:${PATH}"
ENV JAVA_HOME="/opt/java/openjdk"

WORKDIR /app
COPY .mvn ./.mvn
COPY pom.xml .
RUN mvnd dependency:go-offline -B
COPY src ./src

CMD ["mvnd", "clean", "install", "-Dmaven.build.cache.enabled=true"]