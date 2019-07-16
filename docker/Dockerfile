FROM debian:stretch
LABEL maintainer="SecureTag Developers <dev@securetagpay.org>"
LABEL description="Dockerised SecureTag, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
