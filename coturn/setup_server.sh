container_name=coturn

docker run -d --rm \
  -p 3478:3478 \
  --name "${container_name}" \
  -p 49152-65535:49152-65535/udp coturn/coturn:4.5
