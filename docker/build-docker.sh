#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-securetagpay/securetagd-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/securetagd docker/bin/
cp $BUILD_DIR/src/securetag-cli docker/bin/
cp $BUILD_DIR/src/securetag-tx docker/bin/
strip docker/bin/securetagd
strip docker/bin/securetag-cli
strip docker/bin/securetag-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker
