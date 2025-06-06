#!/usr/bin/env bats

setup() {
  mkdir -p /dev/net
  touch /dev/net/tun
  export OPENVPN_SHAPESHIFTER_LIB=1
  mkdir -p /etc/openvpn/easy-rsa/pki/issued /etc/openvpn/easy-rsa/pki/private
  echo "client" > /etc/openvpn/client-without-common.txt
  echo "CA CERT" > /etc/openvpn/easy-rsa/pki/ca.crt
  echo "CERT" > /etc/openvpn/easy-rsa/pki/issued/testuser.crt
  echo "KEY" > /etc/openvpn/easy-rsa/pki/private/testuser.key
  echo "TA" > /etc/openvpn/ta.key
}

teardown() {
  rm -f /dev/net/tun
  rmdir /dev/net 2>/dev/null || true
  rm -rf /etc/openvpn
  rm -f ~/testuser-withoutobfs.ovpn
  unset OPENVPN_SHAPESHIFTER_LIB
}

@test "newclientwithout generates a single ca tag" {
  source ./setup.sh
  newclientwithout testuser
  run grep -c '<ca>' ~/testuser-withoutobfs.ovpn
  [ "$status" -eq 0 ]
  [ "$output" -eq 1 ]
}
