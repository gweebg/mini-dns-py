#!/bin/sh

mkdir services
cp -r /home/core/Desktop/mini-dns-py/ services/

MODULE="dns.server.resolution_server"
CONFIG="/home/core/Documents/dns-configuration/configuration-files/resolution/configuration_resolution_sp.conf"
PORT="20004"
TIMEOUT="1220"

LAUNCH="python3.10 -m $MODULE -c $CONFIG -p $PORT -t $TIMEOUT"

echo "#!/bin/sh" > launch.sh
echo "cd services/mini-dns-py/src" >> launch.sh
echo "$LAUNCH -d" >> launch.sh
