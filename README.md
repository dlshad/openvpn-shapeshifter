openvpn-shapeshifter Installer for Ubuntu & Debian servers.

This script will automatically guide you to install and configure your OpenVPN server with Shapeshifter Dispatcher
(obfuscation) which will allow you to bypass the DPI blockage on OpenVPN.
This setup will offer the users the freedom to choose between regular OpenVPN connection or obfuscated one, they actually
can use both!  OpenVPN is the VPN provider, Dispatcher is the command line proxy tool which utilize Shapeshifter which is a protocol shapeshifting technology that will obfuscate the transformed data between the user and the server.

How this thing work?

1- This is how OpenVPN works in uncensored network:

+----------+                    +---------------------+                    +----------+
|          |  OpenVPN Traffic   |                     |  OpenVPN Traffic   |          |
|   VPN    <--------------------+      Internet       <--------------------+   VPN    |
|  Server  |                    |                     |                    |  client  |
|          |                    |                     |                    |          |
+----------+                    +---------------------+                    +----------+

2- This is how DPI filtering works:
+----------+                    +----------------+        +-------+        +----------+
|          |                    |                |        |       | OpenVPN|          |
|   VPN    |                    |    Internet    |        |  DPI  <--------+   VPN    |
|  Server  |                    |                |        | Filter| Traffic|  Server  |
|          |                    |                |        |       |        |          |
+----------+                    +----------------+        +-------+        +----------+
                                                           OpenVPN
                                                          traffic is
                                                          Not Allowed
                                                            To pass
                                                            
3- This is how openvpn-shapeshifter works in censored network:
+--------------------+                                                   +--------------------+
|  +--------------+  |                                                   |  +--------------+  |
|  |OpenVPN Server|  |                                                   |  |OpenVPN Client|  |
|  +------^-------+  |       +-----------+           +-----------+       |  +-------+------+  |
|         |          |       |           |           |           |       |          |         |
|         |          |       |           | obfuscated| DPI Filter|       |          |         |
|  OpenVPN|Traffic   |       | Internet  <-----------+ No OpenVPN|       |   OpenVPN|Traffic  |
|         |          |       |           |  traffic  | is allowed|       |          |         |
|         |          |       |           |           |           |       |          |         |
|         |          |       +-----+-----+           +-----^-----+       |          |         |
|  +------+-------+  |             |                       |             |  +-------v------+  |
|  |D|Shapeshifter<----------------+                       +----------------+D|Shapeshifter|  |
|  +--------------+  |   Obfuscated                         Obfuscated   |  +--------------+  |
+--------------------+    Traffic                             Traffic    +--------------------+
