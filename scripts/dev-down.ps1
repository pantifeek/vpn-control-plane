$ErrorActionPreference = "Stop"

$composeFile = "infra/docker/docker-compose.yml"

docker compose -f $composeFile down

$runtimeContainers = docker ps -aq --filter "label=com.vpn-control-plane.runtime.managed=true"

if ($runtimeContainers) {
  docker rm -f $runtimeContainers
}
