#!/bin/bash

ip addr add 10.0.5.1/24 dev ivpn0
ifconfig ivpn0 up
route add -net 10.0.4.0 netmask 255.255.255.0 dev ivpn0
sysctl net.ipv4.ip_forward=1
route add -net 10.0.10.0 netmask 255.255.255.0 gw 10.0.20.1
route add -net 10.0.10.0 netmask 255.255.255.0 dev ivpn0

