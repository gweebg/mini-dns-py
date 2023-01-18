#!/bin/sh

mkdir services
cp -r /home/core/Desktop/mini-dns-py/ services/

echo "#!/bin/sh" > launch.sh
echo "cd services/mini-dns-py/src" >> launch.sh
echo "python3.10 -m dns.server.server -c /home/core/Documents/dns-configuration/configuration-files/zaibatsu.conf -p 20000 -t 20000 --recursive -d -r" >> launch.sh

