#!/bin/sh

mkdir services
cp -r /home/core/Desktop/mini-dns-py/ services/

MODULE="dns.server.server"
CONFIG="/home/core/Documents/dns-configuration/configuration-files/zaibatsu./configuration_zaibatsu.conf"
PORT="20000"
TIMEOUT="1220"

LAUNCH="python3.10 -m $MODULE -c $CONFIG -p $PORT -t $TIMEOUT"

echo "#!/bin/sh" > launch.sh
echo "cd services/mini-dns-py/src" >> launch.sh
echo "$LAUNCH --recursive -d -r" >> launch.sh
