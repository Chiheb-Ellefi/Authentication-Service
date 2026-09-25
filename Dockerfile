ARG BASE_DISTRO=eclipse-temurin
ARG JDK_VERSION=25-jdk
ARG JRE_VERSION=25-jre


#------- Stage 1 : Build --------

FROM ${BASE_DISTRO}:${JDK_VERSION} AS build
LABEL authors="chihebellefi"
WORKDIR /app

COPY .mvn .mvn
COPY  mvnw .
COPY pom.xml .

RUN chmod +x mvnw
RUN ./mvnw dependency:go-offline

COPY src src
RUN ./mvnw clean package -DskipTests

#------- Stage 2 : Runtime --------
FROM ${BASE_DISTRO}:${JRE_VERSION} AS runtime
ENV SERVER_PORT=9000

RUN groupadd -r auth && useradd -r -g auth -u 1001 auth
USER auth
COPY --from=build --chown=auth:auth app/target/*.jar app.jar
EXPOSE ${SERVER_PORT}

ENTRYPOINT ["java", "-jar","app.jar"]