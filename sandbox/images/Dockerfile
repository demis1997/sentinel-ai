# Operator-supplied audited image, containing Python, Slither, Semgrep and a fixed solc.
# Supply a registry reference pinned with @sha256; never build from untrusted sources.
ARG TOOLCHAIN_IMAGE
FROM ${TOOLCHAIN_IMAGE}
USER root
COPY analyze.py rules.yml slither.json /opt/sentinel/
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/python", "/opt/sentinel/analyze.py"]
