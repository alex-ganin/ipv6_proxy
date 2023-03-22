#!/bin/bash

#DEBUG
#set -x
LOCALIPV4="" #public ipv4
HEIPV4SERVER="" #ipv4 address server
HEIPV6CLIENT="" #ipv6 address vps
TUNNELNAME="he-ipv6"
#3Proxy
PORTPROXY=20000 # Proxy port start
CONFIGPROXY="/etc/3proxy/3proxy.cfg"
USERPROXY=login #proxy login
PASSPROXY=passw #proxy password
#ipv6 address
MAXCOUNT=500 #address count
network="" #ipv6 network
####
echo "-------------------------------------------------"
echo ">-- Updating packages and installing dependencies"
apt-get update >/dev/null 2>&1
apt-get -y install gcc g++ make bc pwgen git vim curl htop build-essential speedtest-cli wget psmisc net-tools>/dev/null 2>&1

####
echo ">-- Setting up sysctl.conf"
cat >>/etc/sysctl.conf <<END
net.ipv6.conf.eth0.proxy_ndp=1
net.ipv6.conf.all.proxy_ndp=1
net.ipv6.conf.default.forwarding=1
net.ipv6.conf.all.forwarding=1
net.ipv6.ip_nonlocal_bind=1
net.ipv4.ip_local_port_range=1024 64000
net.ipv6.route.max_size=409600
net.ipv4.tcp_max_syn_backlog=4096
net.ipv6.neigh.default.gc_thresh3=102400
kernel.threads-max=1200000
kernel.max_map_count=6000000
vm.max_map_count=6000000
kernel.pid_max=2000000
END

####
echo ">-- Setting up logind.conf"
echo "UserTasksMax=1000000" >>/etc/systemd/logind.conf

####
echo ">-- Setting up system.conf"
cat >>/etc/systemd/system.conf <<END
UserTasksMax=1000000
DefaultMemoryAccounting=no
DefaultTasksAccounting=no
DefaultTasksMax=1000000
UserTasksMax=1000000
END

echo "-------------------------------------------------"
echo ">-- Generate ipv6 address"
array=( 1 2 3 4 5 6 7 8 9 0 a b c d e f )
count=1

echo -ne > ip.list
echo -ne > ip-add.sh

rnd_ip_block ()
{
   a=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
   b=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
   c=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
   d=${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}${array[$RANDOM%16]}
   echo $network:$a:$b:$c:$d >> ip.list
   echo ip -6 addr add $network:$a:$b:$c:$d dev he-ipv6 >> ip-add.sh
}

while [ "$count" -le $MAXCOUNT ]
do
       rnd_ip_block
       let "count += 1"
done

chmod +x *.sh


echo "-------------------------------------------------"
echo ">-- Add ipv6 address to system interface"
modprobe ipv6

ip tunnel add $TUNNELNAME mode sit remote $HEIPV4SERVER local $LOCALIPV4 ttl 255
ip link set $TUNNELNAME up
./ip-add.sh
ip route add ::/0 dev $TUNNELNAME


echo "-------------------------------------------------"
echo ">-- Create config 3proxy"

### clean cfg ###
echo -ne > /etc/3proxy/3proxy.cfg
echo -ne > proxy.txt

### cfg start ###
echo "daemon" >> $CONFIGPROXY
echo "maxconn 300" >> $CONFIGPROXY
echo "nserver [2606:4700:4700::1111]" >> $CONFIGPROXY
echo "nserver [2606:4700:4700::1001]" >> $CONFIGPROXY
echo "nserver [2001:4860:4860::8888]" >> $CONFIGPROXY
echo "nserver [2001:4860:4860::8844]" >> $CONFIGPROXY
echo "nserver [2a02:6b8::feed:0ff]" >> $CONFIGPROXY
echo "nserver [2a02:6b8:0:1::feed:0ff]" >> $CONFIGPROXY
echo "nscache 65536" >> $CONFIGPROXY
echo "nscache6 65536" >> $CONFIGPROXY
echo "timeouts 1 5 30 60 180 1800 15 60" >> $CONFIGPROXY
echo "stacksize 6000" >> $CONFIGPROXY
echo "flush" >> $CONFIGPROXY
echo "auth strong" >> $CONFIGPROXY
echo "users $USERPROXY:CL:$PASSPROXY" >> $CONFIGPROXY
echo "allow $USERPROXY" >> $CONFIGPROXY

for i in `cat ip.list`; do
    echo "socks -6 -s0 -n -a -olSO_REUSEADDR,SO_REUSEPORT -ocTCP_TIMESTAMPS,TCP_NODELAY -osTCP_NODELAY,SO_KEEPALIVE -p$PORTPROXY -i$LOCALIPV4 -e$i" >> $CONFIGPROXY
    ((inc+=1))
    ((PORTPROXY+=1))
    echo "socks5://$USERPROXY:$PASSPROXY@$LOCALIPV4:$PORTPROXY" >> proxy.txt
done

echo "-------------------------------------------------"
echo ">-- Starting 3proxy"
killall 3proxy
systemctl restart 3proxy.service

echo "-------------------------------------------------"
echo ">-- Clearing..."
rm ip-add.sh
rm ip.list
