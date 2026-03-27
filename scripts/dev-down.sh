#!/usr/bin/env bash
set -e

docker compose -f infra/docker/docker-compose.yml down

RUNTIME_CONTAINERS=$(docker ps -aq --filter "label=com.vpn-control-plane.runtime.managed=true")

if [ -n "$RUNTIME_CONTAINERS" ]; then
  docker rm -f $RUNTIME_CONTAINERS
fi
