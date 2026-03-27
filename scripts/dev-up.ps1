$ErrorActionPreference = "Stop"

$composeFile = "infra/docker/docker-compose.yml"

docker compose -f $composeFile build `
  manager-api `
  manager-web `
  vpn-runtime-openvpn `
  vpn-runtime-ipsec `
  vpn-runtime-wireguard

docker compose -f $composeFile up manager-api manager-web
