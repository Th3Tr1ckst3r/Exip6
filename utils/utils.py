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
import time
import nmap3
import ipaddress
import dns.resolver
import dns.reversename
from scapy.all import *
from scapy.all import get_if_list
from multiprocessing import Process
from mac_vendor_lookup import MacLookup


def is_valid_ipv6(ipv6_addr=None):
    """Check if a string is a valid IPv6 address."""
    try:
        ip = ipaddress.IPv6Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_ipv4(ipv4_addr=None):
    """Check if a string is a valid IPv4 address."""
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(ipv4_pattern, address) is not None


def is_valid_domain(domain=None):
    """Check if a string is a valid domain name."""
    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,}$"
    return re.match(domain_pattern, domain) is not None


def resolve_ipv4_to_domain(ipv4_addr=None, nameserver='1.1.1.1', timeout=5, verbose=False):
    """Resolves public IPv4 addresses to domains. Nameserver address can be changed if argument is passed."""
    if verbose:
        print(f"\nResolving IPv4 address {ipv4_addr} to domain using nameserver {nameserver}...")
    try:
        reverse_name = dns.reversename.from_address(ipv4_addr)
        if verbose:
            print(f"\nReverse DNS name for {ipv4_addr}: {reverse_name}")
        answers = dns.resolver.resolve(reverse_name, 'PTR', nameserver=nameserver)
        domain_name = answers[0].to_text()
        if verbose:
            print(f"\nDomain name for {ipv4_addr} is: {domain_name}")
        return domain_name
    except Exception as e:
        if verbose:
            print(f"\nError resolving {ipv4_addr}: {e}")
        return None


def resolve_domain_to_ipv6(domain_name=None, nameserver='1.1.1.1', timeout=5, verbose=False):
    """Resolves public domains to IPv6 addresses. Nameserver address can be changed if argument is passed."""
    if verbose:
        print(f"Resolving domain {domain_name} to IPv6 addresses using nameserver {nameserver}...")
    try:
        answers = dns.resolver.resolve(domain_name, 'AAAA', nameserver=nameserver)
        ipv6_addresses = [answer.to_text() for answer in answers]
        if verbose:
            print(f"\nIPv6 addresses for domain {domain_name}: {ipv6_addresses}")
        return ipv6_addresses
    except Exception as e:
        if verbose:
            print(f"\nError resolving {domain_name}: {e}")
        return None


def resolve_ipv4_to_ipv6(ipv4_addr=None, nameserver='1.1.1.1', timeout=5, verbose=False):
    """Resolves public IPv4 addresses to IPv6 public addresses."""
    if verbose:
        print(f"\nResolving IPv4 address {ipv4_addr} to IPv6 addresses...")
    domain_name = resolve_ipv4_to_domain(ipv4_addr, nameserver, verbose=verbose)
    if domain_name:
        return resolve_domain_to_ipv6(domain_name, nameserver, verbose=verbose)
    if verbose:
        print(f"\nCould not resolve IPv4 address {ipv4_addr} to domain or domain to IPv6 addresses.")
    return None


def get_interface(interface=None, gateway="192.168.0.1", verbose=False, timeout=5):
    """Function responsible for automatically determining the best interface to use."""
    if verbose:
        print(f"\nStarting interface detection. Gateway: {gateway}")

    interfaces = get_if_list()
    if verbose:
        print(f"\nAvailable interfaces: {interfaces}")

    # Validate if a specific interface is provided and exists
    if interface and interface in interfaces:
        if verbose:
            print(f"\nTesting provided interface: {interface}")
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway)
        responses, _ = srp(arp_request, iface=interface, timeout=timeout, verbose=verbose)
        if responses:
            if verbose:
                print(f"\nResponses received on interface: {interface}")
            return interface

    # If no specific interface is provided or the provided interface was invalid, test all interfaces
    for iface in interfaces:
        if verbose:
            print(f"\nTesting interface: {iface}")
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway)
            responses, _ = srp(arp_request, iface=iface, timeout=timeout, verbose=verbose)
            if responses:
                if verbose:
                    print(f"\nResponses received on interface: {iface}")
                return iface
        except OSError as e:
            if verbose:
                print(f"\nError with interface {iface}: {e}")
            continue

    if verbose:
        print("\nNo suitable interface found.")
    return None


def arp_scan_local(cidr='192.168.0.1/24', interface=None, verbose=False, timeout=5):
    """Discover IPv4 addresses, & MAC addresses of devices on the local network."""
    if verbose:
        print(f"\nPerforming ARP scan on CIDR: {cidr}...")
    arp_request = ARP(pdst=cidr)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast/arp_request
    if verbose:
        print(f"\nSending ARP requests on interface {interface}...")
    responses, _ = srp(arp_packet, timeout=timeout, iface=interface, verbose=verbose)
    mac_dict = {}
    for _, response in responses:
        if response.haslayer(Ether):
            ip_addr = response[ARP].psrc
            mac_addr = response[Ether].src
            try:
                mac_vendor = MacLookup().lookup(str(mac_addr))
            except:
                mac_vendor = None
            mac_dict[ip_addr] = [mac_addr, mac_vendor]
            if verbose:
                if mac_vendor:
                    print(f"\nDiscovered IP: {ip_addr}, MAC Address: {mac_addr}, MAC Vendor: {mac_vendor}")
                else:
                    print(f"\nDiscovered IP: {ip_addr}, MAC Address: {mac_addr}, MAC Vendor: Unknown")
    if verbose:
        print(f"\nARP scan complete. Found {len(mac_dict)} devices.")
    return mac_dict


def sniff_ipv6_local(interface=None, verbose=False, sniff_duration=30, network_prefix='fe80::1/16', disable_ra=False):
    """
    Sniffs IPv6 packets and maps IPv6 addresses to MAC addresses,
    ignoring packets from the local interface's MAC address.
    """
    ipv6_mac_dict = {}
    local_mac_address = get_if_hwaddr(interface)

    def process_packet(packet):
        if IPv6 in packet and Ether in packet:
            ipv6_src = packet[IPv6].src
            mac_src = packet[Ether].src
            if mac_src != local_mac_address and ipv6_src not in ipv6_mac_dict:
                try:
                    mac_vendor = MacLookup().lookup(str(mac_src))
                except:
                    mac_vendor = None
                ipv6_mac_dict[ipv6_src] = [mac_src, mac_vendor]
                if verbose:
                    mac_vendor_info = mac_vendor or 'Unknown'
                    print(f"\nCaptured IPv6 Address: {ipv6_src}, MAC Address: {mac_src}, MAC Vendor: {mac_vendor_info}")

    if not disable_ra:
        ra_process = Process(target=send_ra_packets, args=(interface, network_prefix, verbose,))
        ra_process.start()

    if verbose:
        print(f"\nSniffing on interface {interface} for {sniff_duration} seconds...")

    sniff(iface=interface, filter="ip6", prn=process_packet, timeout=sniff_duration)

    if not disable_ra:
        ra_process.terminate()

    if verbose:
        print("\nFinished sniffing.")

    return ipv6_mac_dict


def detect_os(ipv4_addr=None):
    """
    Use Nmap3 to perform OS detection on the target IP address. IPv4 only supported.
    We cross reference the MAC addresses from our ARP scan with that of the MAC addresses
    we get from sniffing on IPv6 to determine which are Windows to better determine which
    are most likely to be vulnerable IE WINDOWS.
    """
    nm = nmap3.Nmap()
    try:
        # Perform OS detection using Nmap3
        scan_result = nm.nmap_os_detection(ipv4_addr)
        #print("Raw scan result:", scan_result)  # Debugging line
        
        # Extract and print the OS match information
        if 'osmatch' in scan_result[ipv4_addr]:
            os_match = scan_result[ipv4_addr]['osmatch'][0]
            osclass = os_match.get('osclass', {})
            osfamily = osclass.get('osfamily', 'Unknown')
            return osfamily
        else:
            return None
    except Exception as e:
        return None


def send_ra_packets(interface=None, network_prefix='fe80::1/16', verbose=False):
    try:
        # Get the MAC address of the specified interface
        mac_address = get_if_hwaddr(interface)
        
        # Extract a global unicast address from the network prefix
        # This example uses the first address in the range. Adjust as necessary.
        global_unicast_src = network_prefix.split('/')[0]  # Assumes global address in prefix

        # Create the RA template
        ra_template = IPv6(dst="ff02::1", src=global_unicast_src) / ICMPv6ND_RA()
        ra_template /= ICMPv6NDOptMTU(mtu=1500)
        ra_template /= ICMPv6NDOptSrcLLAddr(lladdr=mac_address)

        if verbose:
            print("\nStarted Router Advertisement broadcast...")
            #ra_template.show()
        

        while True:
            # Create the full packet with the source MAC address of the interface
            packet = Ether(src=mac_address, dst="33:33:00:00:00:01") / ra_template
            sendp(packet, iface=interface, verbose=verbose)
            time.sleep(5)
    except:
        if verbose:
            print('\nEnded Router Advertisement broadcast...')
        sys.exit(1)
        


def nmap_worker(ipv4_addr=None, mac_addr=None, mac_vendor=None, verbose=False, ipv4_potential_targets=None):
    os = detect_os(ipv4_addr)
    if os == 'Windows':
        ipv4_potential_targets[ipv4_addr] = [mac_addr, mac_vendor]
        print(f'\nPotentially vulnerable Windows device found, IPv4 Address: {ipv4_addr}, MAC Address: {mac_addr}, Mac Vendor: {mac_vendor}.')
        return True
    else:
        if verbose:
            if os:
                print(f'\nUnrelated {os} device found, IPv4 Address: {ipv4_addr}, MAC Address: {mac_addr}, Mac Vendor: {mac_vendor}.')
                return False
            else:
                print(f'\nUnable to detect operating system on a located device, IPv4 Address: {ipv4_addr}, MAC Address: {mac_addr}, Mac Vendor: {mac_vendor}.')
                return False
        else:
            return False