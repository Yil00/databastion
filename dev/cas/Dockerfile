# Apereo CAS dev image (opt-in Compose profile `cas`, dev/README.md "Apereo CAS"). DEV ONLY: never
# part of the release assets; it carries no secret (dev/.env provides the dev-only values at run
# time).
#
# The published apereo/cas image is the CAS overlay with the core modules only: no JSON service
# registry, no OIDC, no JPA ticket registry (ADR-0041 open question 7). This build adds them to its
# war from pinned sources (the maintainer's answer to that question):
#   1. `modules`: Gradle resolves the modules against the CAS and Spring Boot BOMs of the war, with
#      every version locked (overlay/gradle.lockfile) and every file checked against
#      overlay/gradle/verification-metadata.xml (SHA-256, --dependency-verification strict);
#   2. `war`: overlay/merge.py adds the jars the war lacks and fails on any version conflict;
#   3. the final image is the pinned apereo/cas image with that war, run as an unprivileged user.
# A new CAS version: change the three versions below together, then regenerate the lock and the
# verification metadata (overlay/build.gradle, first comment).
ARG CAS_IMAGE=apereo/cas:8.0.2@sha256:475b77a5cc7bf421853ec57bf469b42c54fe1a65ecda7eaff782b117ad49f212
ARG GRADLE_IMAGE=gradle:9.8.0-jdk25@sha256:7086a4cd10d568b35cafd6d5d30323865f3ce1f23ccddc9570ff3e3c9c8cd6e9
ARG CAS_VERSION=8.0.2
ARG SPRING_BOOT_VERSION=4.1.0

FROM ${CAS_IMAGE} AS cas

FROM ${GRADLE_IMAGE} AS modules
ARG CAS_VERSION
ARG SPRING_BOOT_VERSION
WORKDIR /overlay
COPY overlay/settings.gradle overlay/build.gradle overlay/gradle.lockfile ./
COPY overlay/gradle/verification-metadata.xml gradle/verification-metadata.xml
RUN gradle --no-daemon --quiet --dependency-verification strict \
      -PcasVersion="$CAS_VERSION" -PspringBootVersion="$SPRING_BOOT_VERSION" modules \
    && mv build/modules /modules

FROM ${GRADLE_IMAGE} AS war
ARG CAS_VERSION
ARG SPRING_BOOT_VERSION
COPY overlay/merge.py /merge.py
COPY --from=cas /docker/cas/war/cas.war /in/cas.war
COPY --from=modules /modules /modules
RUN mkdir /out && python3 /merge.py /in/cas.war /modules "$CAS_VERSION" "$SPRING_BOOT_VERSION" /out/cas.war

FROM ${CAS_IMAGE}
COPY --from=war /out/cas.war /docker/cas/war/cas.war
# The CAS user (uid / gid 10041) owns its state (OIDC keystore) and the audit log; the registry and
# the configuration are mounted read-only. The image's /etc/cas/services stays empty and unused
# (the registry is mounted over it).
RUN groupadd --system --gid 10041 cas \
    && useradd --system --uid 10041 --gid 10041 --home-dir /var/lib/cas --no-create-home \
         --shell /usr/sbin/nologin cas \
    && install -d -o cas -g cas -m 0750 /var/lib/cas \
    && install -d -o cas -g cas -m 0750 /var/log/cas
USER 10041:10041
ENV HOME=/var/lib/cas
