FROM container-registry.oracle.com/graalvm/native-image:24 AS builder

RUN microdnf install findutils

WORKDIR /server
COPY . /server
RUN ./gradlew nativeCompile

FROM oraclelinux:9-slim

EXPOSE 8080

COPY --from=builder /server/build/native/nativeCompile/permissionizer-server permissionizer-server

ENTRYPOINT ["/permissionizer-server"]
