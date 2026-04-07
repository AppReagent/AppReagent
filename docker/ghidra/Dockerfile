FROM eclipse-temurin:21-jdk-noble

ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip

RUN apt-get update && apt-get install -y wget unzip && \
    wget -q "${GHIDRA_URL}" -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_* /opt/ghidra && \
    rm /tmp/ghidra.zip && \
    apt-get remove -y wget unzip && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

ENV GHIDRA_HOME=/opt/ghidra
ENV JAVA_HOME=/opt/java/openjdk

WORKDIR /work
ENTRYPOINT ["/opt/ghidra/support/analyzeHeadless"]
