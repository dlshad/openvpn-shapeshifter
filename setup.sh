#!/bin/bash
# Shell installer of obfuscated OpenVPN via shapeshifter-dispatcher pluggable transport
# This script will work on Debian and Ubuntu
# Ability to enable obfuscation was added to the script to help users suffering from DPI censorship for more information https://pluggabletransports.info
#Credits: To https://github.com/Nyr/openvpn-install for the orignal openvpn-install script and OperatorFoundation for the awesome shapeshifter-dispatcher.
#By @dlshadothman https://github.com/dlshad 


# Detect if the user is running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -qs "dash"; then
	echo "This script needs to be run with bash, not sh"
	exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit 2
fi

# Detect if the kernel supports TUN 
if [[ ! -e /dev/net/tun ]]; then
	echo "TUN is not available read more about it here https://crybit.com/how-to-enablecheck-tuntap-module-in-vpsopenvz/"
	exit 3
fi

# Detect if the user running the script on Debian or Ubuntu 
if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL='/etc/rc.local'
else
	echo "Looks like you aren't running this installer on a Debian or Ubuntu system"
	exit 5
fi

# Generates custom CLIENT.ovpn file
newclient () {
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	cat /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

# Generates custom CLIENT-withoutobfs.ovpn file
newclientwithout () {
	cp /etc/openvpn/client-without-common.txt ~/$1-withoutobfs.ovpn
	echo "<ca>" >> ~/$1-withoutobfs.ovpn
	echo "<ca>" >> ~/$1-withoutobfs.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1-withoutobfs.ovpn
	echo "</ca>" >> ~/$1-withoutobfs.ovpn
	echo "<cert>" >> ~/$1-withoutobfs.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1-withoutobfs.ovpn
	echo "</cert>" >> ~/$1-withoutobfs.ovpn
	echo "<key>" >> ~/$1-withoutobfs.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1-withoutobfs.ovpn
	echo "</key>" >> ~/$1-withoutobfs.ovpn
	echo "<tls-auth>" >> ~/$1-withoutobfs.ovpn
	cat /etc/openvpn/ta.key >> ~/$1-withoutobfs.ovpn
	echo "</tls-auth>" >> ~/$1-withoutobfs.ovpn
}

# Generates custom bash file installer for client CLIENT.sh
newclientbash () {
	cp /etc/openvpn/client-bash-common.txt ~/$1.sh
	sed -i 's/clientvpnfile/'$CLIENT'/g' ~/$1.sh
}

# Obtaining the public IP v4 address of the server 
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -qO- ipv4.icanhazip.com)
fi

#Check if OpenVPN server and pluggabletransport are installed
if [[ -f /etc/openvpn/server.conf && -f /usr/bin/go && -f /bin/shapeshifter-dispatcher ]] 
then
		clear
	while :
	do
	clear
		echo "Now you can run obfuscated openVPN"
		echo ""
		echo "What do you want to do?"
		echo "   1) Add a cert for a new user"
		echo "   2) Revoke existing user cert"
		echo "   3) Remove OpenVPN & pluggable transport"
		echo "   4) Exit"
		read -p "Select an option [1-4]: " option
		case $option in
			1)
			echo ""
			echo "Tell me a name for the client cert"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			cd /etc/openvpn/easy-rsa/
			./easyrsa build-client-full $CLIENT nopass
			
			# Generates custom CLIENT.ovpn file
			newclient "$CLIENT"
			# Generates custom CLIENT-withoutobfs.ovpn file
			newclientwithout "$CLIENT"
			# Generates custom bash file installer for client CLIENT.sh
			newclientbash "$CLIENT"
			
			clear			
			echo ""
			echo "Client $CLIENT added, configuration is available at" ~/"$CLIENT.ovpn"
			echo "Client $CLIENT added, configuration for OpenVPN without obfuscation is available at" ~/"$CLIENT-withoutobfs.ovpn"
			echo "We already created a bash file for your client to run in order to setup and run openvpn-dispatcher you can find it here" ~/"$CLIENT.sh"			
			exit
			;;
			2)
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "You have no existing clients!"
				exit 6
			fi
			echo ""
			echo "Select the existing client certificate you want to revoke"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Select one client [1]: " CLIENTNUMBER
			else
				read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/easy-rsa/
			./easyrsa --batch revoke $CLIENT
			./easyrsa gen-crl
			rm -rf pki/reqs/$CLIENT.req
			rm -rf pki/private/$CLIENT.key
			rm -rf pki/issued/$CLIENT.crt
			rm -rf /etc/openvpn/crl.pem
			cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
			
			# CRL is read with each client connection, when OpenVPN is dropped to nobody
			chown nobody:$GROUPNAME /etc/openvpn/crl.pem
			echo ""
			echo "Certificate for client $CLIENT revoked"
			exit
			;;

			3)
			echo ""
			read -p "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
			if [[ "$REMOVE" = 'y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --zone=public --remove-port=$PORT/tcp
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/tcp
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
				fi
				if iptables -L -n | grep -qE 'REJECT|DROP'; then
					sed -i "/iptables -I INPUT -p tcp --dport $PORT -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
				fi
				sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
				if hash sestatus 2>/dev/null; then
					if sestatus | grep "Current mode" | grep -qs "enforcing"; then
						if [[ "$PORT" != '1194' ]]; then
							semanage port -d -t openvpn_port_t -p tcp $PORT
						fi
					fi
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn openvpn-blacklist golang 
					apt autoremove -y
				fi
				/etc/init.d/dispatcher stop
				rm -rf /etc/openvpn
				rm -rf /usr/share/doc/openvpn*
				rm -rf ~/go
				#Remove dispatcher service
				rm /etc/init.d/dispatcher
				#Remove dispatcher from system startup
				sed -i.bak '/dispatcher/d' /etc/rc.local
				echo ""
				echo "OpenVPN, Golang and shapeshifter-dispatcher removed!"
			else
				echo ""
				echo "Removal aborted!"
			fi
			exit
			;;
			4)
			exit;;

		esac
	done

else
	clear
	echo "Welcome to this quick obfuscated OpenVPN installer"
	echo ""
	# OpenVPN & pluggable transport setup and first user creation
	echo "I need to ask you few questions before starting the setup"
	echo "You can leave the default options and just press enter if you are ok with them"
	echo ""
	echo "First I need to know the IPv4 address of the network interface you want OpenVPN"
	echo "to listen. Please note that the script will obtain the public IP address of your server "
	read -p "IP address: " -e -i $IP IP
	echo ""
	echo "Which port are you going to use for for OpenVPN?"
	read -p "Port: " -e -i 1194 PORT
	echo ""
	echo "Which port are you going to use for for shapeshifter-dispatcher (obfuscation)?"
	read -p "Port: " -e -i 5743 OBFSPORT
	echo "Which DNS do you want to use for the VPN?"
	echo "   1) Current system resolvers"
	echo "   2) Google"
	echo "   3) OpenDNS"
	echo "   4) NTT"
	echo "   5) Hurricane Electric"
	echo "   6) Verisign"
	read -p "DNS [1-6]: " -e -i 1 DNS
	echo ""
	echo "Finally, enter the name of the client cert"
	echo "Please, use one word only, no special characters"
	read -p "Client name: " -e -i client CLIENT
	echo ""
	echo "Okay, this is all what I needed. We are ready to setup your OpenVPN server now"
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates git golang curl -y
		mkdir ~/go
		export GOPATH=~/go
		go get -u github.com/OperatorFoundation/shapeshifter-dispatcher/shapeshifter-dispatcher
		#configuring dispatcher as server
		echo '#!/bin/sh
		### BEGIN INIT INFO
		# Provides:
		# Required-Start:    $remote_fs $syslog
		# Required-Stop:     $remote_fs $syslog
		# Default-Start:     2 3 4 5
		# Default-Stop:      0 1 6
		# Short-Description: Start daemon at boot time
		# Description:       Enable service provided by daemon.
		### END INIT INFO

		dir="/root/go" 
		cmd="bin/shapeshifter-dispatcher -server -transparent -ptversion 2 -transports obfs2 -state state -bindaddr obfs2-'$IP':'$OBFSPORT' -orport 127.0.0.1:'$PORT' &" 
		user=""
		name=`basename $0`
		pid_file="/var/run/$name.pid"
		stdout_log="/var/log/$name.log"
		stderr_log="/var/log/$name.err"

		get_pid() {
 		       cat "$pid_file"
	       }

	       is_running() {
		       [ -f "$pid_file" ] && ps `get_pid` > /dev/null 2>&1
	       }

	       case "$1" in
		       start)
 		      if is_running; then
        		      echo "Already started"
  		    else
       		     echo "Starting $name"
      	       cd "$dir"
     	   if [ -z "$user" ]; then
       	     sudo $cmd >> "$stdout_log" 2>> "$stderr_log" &
      	  else
      	      sudo -u "$user" $cmd >> "$stdout_log" 2>> "$stderr_log" &
      	  fi
      	  echo $! > "$pid_file"
     	   if ! is_running; then
       	     echo "Unable to start, see $stdout_log and $stderr_log"
      	      exit 1
      	  fi
   	 fi
  	  ;;
  	  stop)
   	 if is_running; then
   	      echo -n "Stopping $name.."
    	    kill `get_pid`
    	    for i in {1..10}
    	    do
        	    if ! is_running; then
          	      break
       	     fi

        	    echo -n "."
       	     sleep 1
      	  done
      	  echo

      	  if is_running; then
      	      echo "Not stopped; may still be shutting down or shutdown may have failed"
       	     exit 1
       	 else
        	    echo "Stopped"
        	    if [ -f "$pid_file" ]; then
        		    rm "$pid_file"
       	     fi
       	 fi
  	  else
    	      echo "Not running"
  	  fi
  	  ;;
  	  restart)
  	  $0 stop
  	  if is_running; then
  		echo "Unable to stop, will not attempt to start"
  	      exit 1
 	   fi
   	 $0 start
 	   ;;
  	  status)
   	 if is_running; then
   	      echo "Running"
   	 else
   	      echo "Stopped"
    	    exit 1
   	 fi
  	  ;;
  	  *)
  	  echo "Usage: $0 {start|stop|restart|status}"
  	  exit 1
  	  ;;
	esac

	exit 0' > /etc/init.d/dispatcher
	#Making /etc/init.d/dispatcher an executable file 
		chmod u+x /etc/init.d/dispatcher
	fi
	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	# Get easy-rsa
	wget -O ~/EasyRSA-3.0.1.tgz https://github.com/OpenVPN/easy-rsa/releases/download/3.0.1/EasyRSA-3.0.1.tgz
	tar xzf ~/EasyRSA-3.0.1.tgz -C ~/
	mv ~/EasyRSA-3.0.1/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.1/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.1.tgz
	cd /etc/openvpn/easy-rsa/
	# Create the PKI, set up the CA, the DH params and the server + client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa build-client-full $CLIENT nopass
	./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	# CRL is read with each client connection, when OpenVPN is dropped to nobody
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	# Generate key for tls-auth
	openvpn --genkey --secret /etc/openvpn/ta.key
	# Generate server.conf
	echo "port $PORT
proto tcp
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf
	# DNS
	case $DNS in
		1)
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2)
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		4)
		echo 'push "dhcp-option DNS 129.250.35.250"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 129.250.35.251"' >> /etc/openvpn/server.conf
		;;
		5)
		echo 'push "dhcp-option DNS 74.82.42.42"' >> /etc/openvpn/server.conf
		;;
		6)
		echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
comp-lzo
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server.conf
	# Enable net.ipv4.ip_forward for the system
	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
	if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then
		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
	fi
	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	# Set NAT for the VPN subnet
	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
	sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP" 
	if pgrep firewalld; then
		# We don't use --add-service=openvpn because that would only work with
		# the default port. Using both permanent and not permanent rules to
		# avoid a firewalld reload.
		firewall-cmd --zone=public --add-port=$PORT/tcp
		firewall-cmd --zone=public --add-port=$OBFSPORT/tcp
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/tcp
		firewall-cmd --permanent --zone=public --add-port=$OBFSPORT/tcp
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
	fi
	if iptables -L -n | grep -qE 'REJECT|DROP'; then
		# If iptables has at least one REJECT rule, we asume this is needed.
		# Not the best approach but I can't think of other and this shouldn't
		# cause problems.
		iptables -I INPUT -p tcp --dport $PORT -j ACCEPT
		iptables -I INPUT -p tcp --dport $OBFSPORT -j ACCEPT
		iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
		iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		sed -i "1 a\iptables -I INPUT -p tcp --dport $PORT -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I INPUT -p tcp --dport $OBFSPORT -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' ]]; then
				semanage port -a -t openvpn_port_t -p tcp $PORT
				semanage port -a -t openvpn_port_t -p tcp $OBFSPORT
			fi
		fi
	fi
	# And finally, start+enable OpenVPN and shapeshifter-dispatcher services
	/etc/init.d/openvpn restart
	systemctl start openvpn@server
	systemctl enable openvpn@server
	/etc/init.d/dispatcher start
	#Running shapeshifter-dispatcher at the system starup
	sed -i "13i /etc/init.d/dispatcher start" /etc/rc.local

	# Try to detect a NATed connection and ask about it to potential LowEndSpirit users
	EXTERNALIP=$(wget -qO- ipv4.icanhazip.com)
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		echo "Looks like your server is behind a NAT!"
		echo ""
		echo "If your server is NATed (e.g. LowEndSpirit), I need to know the external IP"
		echo "If that's not the case, just ignore this and leave the next field blank"
		read -p "External IP: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto tcp
sndbuf 0
rcvbuf 0
remote 127.0.0.1
port 1234
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
comp-lzo
setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/client-common.txt

	# client-without-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto tcp
sndbuf 0
rcvbuf 0
remote $IP
port $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
comp-lzo
setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/client-without-common.txt
	# client-bash-common.txt is created so we have a template to add further users later
	
	echo '#!/bin/bash
	# Shell installer of obfuscated OpenVPN via shapeshifter-dispatcher pluggable transport client, for Debian and Ubuntu
	# This script will work on Debian and Ubuntu
	# Ability to enable obfuscation was added to the script to help users suffering from DPI censorship for more information https://pluggabletransports.info
	#Credits: Thanks to https://github.com/Nyr/openvpn-install for the orignal openvpn-install script which
	#this script was built based on it and OperatorFoundation for shapeshifter-dispatcher
	#@dlshadothman

	if [[ -f /etc/init.d/openvpn && -f /usr/bin/go && -f /bin/shapeshifter-dispatcher ]]; then
		while :
		do
			~/go/bin/shapeshifter-dispatcher -client -transparent -ptversion 2 -transports obfs2 -state state -target '$IP':'$OBFSPORT' &
			disown
			read -n1 -r -p  "shapeshifter-dispatcher obfuscation is running now press anykey to run the openVPN connection"
			openvpn --config clientvpnfile.ovpn
		done
	else
		read -n1 -r -p "You dont have the needed software to run the VPN connection, Press any key to install them..."
			apt-get update
			apt-get install openvpn git golang curl -y
			mkdir ~/go
			export GOPATH=~/go
			go get -u github.com/OperatorFoundation/shapeshifter-dispatcher/shapeshifter-dispatcher
	fi' > /etc/openvpn/client-bash-common.txt

	# Generates custom CLIENT.ovpn file
	newclient "$CLIENT"
	# Generates custom CLIENT-withoutobfs.ovpn file
	newclientwithout "$CLIENT"
	# Generates custom bash file installer for client CLIENT.sh
	newclientbash "$CLIENT"
	
	echo ""
	echo "Finished!"
	echo ""
	echo "Client $CLIENT added, configuration is available at" ~/"$CLIENT.ovpn"
	echo "Client $CLIENT added, configuration for OpenVPN without obfuscation is available at" ~/"$CLIENT-withoutobfs.ovpn"
	echo "We already created a bash file for your client to run in order to setup and run openvpn-dispatcher you can find it here" ~/"$CLIENT.sh"
	echo "If you want to add more clients, you simply need to run this script another time!"
	echo "You have to install OpenVPN, Golang and shapeshifter-dispatcher on the client to be able to use it!"
	echo "Then you have to run the followng command on the client side before establishing the openvpn connection:"
	echo "~/go/bin/shapeshifter-dispatcher -client -transparent -ptversion 2 -transports obfs2 -state state -target $IP:$OBFSPORT"
