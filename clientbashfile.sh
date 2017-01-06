#!/bin/bash
	# Shell installer of obfuscated OpenVPN via shapeshifter-dispatcher pluggable transport client, for Debian and Ubuntu
	# This script will work on Debian and Ubuntu
	# Ability to enable obfuscation was added to the script to help users suffering from DPI censorship for more information https://pluggabletransports.info
	#Credits: Thanks to https://github.com/Nyr/openvpn-install for the orignal openvpn-install script which
	#this script was built based on it and OperatorFoundation for shapeshifter-dispatcher
	#@dlshadothman

	if [[ -f /etc/init.d/openvpn && -f /usr/bin/go && -f /bin/shapeshifter-dispatcher ]]; then
		while :
		do
			shapeshifter-dispatcher -client -transparent -ptversion 2 -transports obfs2 -state state -target $IP:$OBFSPORT
		done
	else
		read -n1 -r -p "You do not have all the needed software to run the VPN connection, Press any key to continue..."
			apt-get update
			apt-get install openvpn git golang curl -y
			mkdir ~/go
			export GOPATH=~/go
			go get -u github.com/OperatorFoundation/shapeshifter-dispatcher/shapeshifter-dispatcher
	fi
