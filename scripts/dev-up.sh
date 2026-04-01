#!/usr/bin/env bash
set -e

docker compose -f infra/docker/docker-compose.yml build \
  manager-api \
  manager-web \
  vpn-runtime-openvpn \
  vpn-runtime-ipsec \
  vpn-runtime-ipsec-b \
  vpn-runtime-wireguard

docker compose -f infra/docker/docker-compose.yml up manager-api manager-web
