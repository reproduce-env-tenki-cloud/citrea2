FROM debian:bookworm-slim
RUN \
  apt-get update \
  && apt-get -y install gettext-base \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/app
COPY . .
RUN rm -rf Dockerfile

ENTRYPOINT ["./run.sh"]


