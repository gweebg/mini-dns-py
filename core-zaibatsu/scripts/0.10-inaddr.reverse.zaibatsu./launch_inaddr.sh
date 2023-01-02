#!/bin/sh

mkdir services
cp -r /home/core/Desktop/mini-dns-py/ services/

MODULE="dns.server.server"
CONFIG="/home/core/Documents/dns-configuration/configuration-files/0.10-inaddr.reverse.zaibatsu/configuration_0.10-inaddr_sp.conf"
PORT="20008"
TIMEOUT="1220"

LAUNCH="python3.10 -m $MODULE -c $CONFIG -p $PORT -t $TIMEOUT"

echo "#!/bin/sh" > launch.sh
echo "cd services/mini-dns-py/src" >> launch.sh
echo "$LAUNCH --recursive -d" >> launch.sh
