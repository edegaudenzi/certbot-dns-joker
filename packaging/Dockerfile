# -*- mode:dockerfile -*-

ARG CERTBOT_VERSION=2.10.0

# https://hub.docker.com/r/certbot/certbot
# The certbot Dockerfile specifies 'ENTRYPOINT [ "certbot" ]'.
FROM certbot/certbot:v${CERTBOT_VERSION}

#### BUILD STAGE

ARG CERTBOT_VERSION
ENV CERTBOT_VERSION=${CERTBOT_VERSION}
ARG CERTBOT_DNS_JOKER_WHL
ARG DOCKER_OTHER_PLUGINS

COPY ${CERTBOT_DNS_JOKER_WHL} /tmp
COPY install-other-plugins /tmp
RUN pip install --no-cache-dir /tmp/${CERTBOT_DNS_JOKER_WHL} \
 && rm /tmp/${CERTBOT_DNS_JOKER_WHL} \
 && /tmp/install-other-plugins ${DOCKER_OTHER_PLUGINS} \
 && rm /tmp/install-other-plugins \
 && : # empty final command.

