# Workload client of the Firebird load run (e2e/load/firebird.sh, e2e/load/README.md "Firebird
# target"): Python with firebird-driver over the client library of the pinned Firebird 5.0.4 image
# (libfbclient, its ChaCha and Srp plugins; protocol-compatible with the 4.0.7 server too). Runs as
# uid 10001 in the server's network namespace (loopback only), every capability dropped; the
# harness's own script e2e/load/fbload.py is mounted read-only. Dev / CI tooling only: never
# published, never part of the agent. The Firebird files are copied from the image as a tool, not
# redistributed (ADR-0060 decision 9).
FROM firebirdsql/firebird:5.0.4@sha256:1529560400fc7847f015c57fc9d70729c44d9a9d8f9000df19c5ce1950b4c202 AS fb

FROM python:3.13-slim-trixie@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: \
      -r /tmp/requirements.txt \
 && rm -f /tmp/requirements.txt
COPY --from=fb /opt/firebird/lib/ /opt/firebird/lib/
COPY --from=fb /opt/firebird/plugins/libChaCha.so /opt/firebird/plugins/libSrp.so /opt/firebird/plugins/
COPY --from=fb /opt/firebird/firebird.msg /opt/firebird/
COPY --from=fb /opt/firebird/intl/ /opt/firebird/intl/
COPY --from=fb /usr/lib/x86_64-linux-gnu/libtommath.so.1* /usr/lib/x86_64-linux-gnu/
# The client's own configuration: wire encryption required (the server requires it too), SRP-256.
RUN printf 'WireCrypt = Required\nWireCryptPlugin = ChaCha64, ChaCha\nAuthClient = Srp256\n' >/opt/firebird/firebird.conf \
 && python3 -c 'import firebird.driver'
ENV FIREBIRD=/opt/firebird LD_LIBRARY_PATH=/opt/firebird/lib HOME=/tmp PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
ENTRYPOINT ["python3", "-I", "/databastion/fbload.py"]
