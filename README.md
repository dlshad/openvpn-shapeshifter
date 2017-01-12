##openvpn-shapeshifter Installer for Ubuntu & Debian servers.

This script will automatically guide you to install and configure your OpenVPN server with Shapeshifter Dispatcher
(obfuscation) which will allow you to bypass the DPI blockage on OpenVPN.
This setup will offer the users the freedom to choose between regular OpenVPN connection or obfuscated one, they actually
can use both!  OpenVPN is the VPN provider, Dispatcher is the command line proxy tool which utilize Shapeshifter which is a protocol shapeshifting technology that will obfuscate the transformed data between the user and the server.

###How this thing work?

1- This is how OpenVPN works in uncensored network:
![OpenVPN_uncensored](/img/OpenVPN_no_DPI.png?raw=true "How OpenVPN works in uncensored network")
2- This is how DPI filtering works:
![OpenVPN_censored](/img/OpenVPN_with_DPI.png?raw=true "How how DPI filtering works")                                         
3- This is how openvpn-shapeshifter works in censored network:
![openvpn-shapeshifter](/img/OpenVPN_Obfs.png?raw=true "How how DPI filtering works")

###Installation
Run the following command in your Ubuntu or Debian server:

`wget https://git.io/vMgOE -O setup.sh && bash setup.sh`

###Tested on
Linode, Digitalocean and AWS.

###Credits

The Operator Foundation for Shapeshifter Dispatcher

NYR https://github.com/Nyr for the original OpenVPN Bash installer 

OpenVPN for OpenVPN!

###Do you need help?
Sure! contact me on dothman@internews.org pgp: http://pgp.mit.edu/pks/lookup?op=get&search=0x432F2FA087E90308
Or! @dlshadothman

Good luck!
