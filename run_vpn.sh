cat run_vpn.sh   

#!/bin/bash
docker pull myelectronix/xtls-reality:latest
docker stop xtls-reality
docker rm xtls-reality


docker run -d \
--restart unless-stopped \
--network host \
-v xtls-reality-volume:/opt/xray/config \
--name xtls-reality \
myelectronix/xtls-reality:latest


echo "Waiting for XRay to start..."
sleep 3

docker logs xtls-reality

echo ""
echo "Client settings:"

docker exec xtls-reality bash get-client-settings.sh
docker exec xtls-reality bash get-client-qr.sh

