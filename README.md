<p align="center">
  <img src="/logo/logo.jpg" alt="Exip6 Logo" width="300">
</p>

# Exip6

[![License](https://img.shields.io/badge/License-GPL%203.0%20with%20AGPL%203.0-blue.svg)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/Th3Tr1ckst3r/Exip6)](https://github.com/Th3Tr1ckst3r/Exip6/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/Th3Tr1ckst3r/Exip6)](https://github.com/Th3Tr1ckst3r/Exip6/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/Th3Tr1ckst3r/Exip6)](https://github.com/Th3Tr1ckst3r/Exip6/issues)

A modern IPv6 discovery, and exploitation toolkit that supports various IPv6 CVE exploits from
the past decade with Python3 & Scapy.

# About
Exip6 started out as a relatively simple tool I built to verify wether my own systems were vulnerable
to a select few of the Windows IPv6 CVE's supported by Exip6. After awhile, I found myself, & 
other researchers using similar tools while trying to debug various IPv6 bugs. As a result, 
this tool became more of a toolkit that we are just building on over time.

## Why Use Exip6?
If your a security researcher, pentester, or just work I.T. in your department. It can be useful when it
comes to the IPv6 protocol for discovery purposes, or just checking if any Windows systems on your network may be vulnerable
to recent bugs.

## Features

- Blazing fast speeds, stability, & control.
- Powered by Python3, Scapy, & NMap with multiprocessing, & even some multithreading.
- Verifiable Proof-of-Concept payloads for testing if systems in your network are vulnerable.
- Two modes to keep things simple which serve as the foundation of the framework: Discovery mode, & Exploit mode.
- Automated IPv6 discovery mode with optimized NMap scanning all being handled in the background.
- Verbose output that can actually be of use when required for debugging even the toughest situations.
- Control over RA packets when discovery matters, but you don't want to trigger your network protection systems.

And more!

## Installation Notice

Exip6 uses Python3 natively, so you will need to have it installed before proceeding. Currently,
Exip6 only supports Linux due to network stack constraints with the Windows operating system, & Scapy.

You will also have to be able to run sudo, or as root user.

Once you have Python3 installed, you can follow the steps below.

## Required Libraries Install Guide

To use Exip6, the following Python3 libraries will need to be installed. You can install them using the Python package manager `pip`.
Below are the installation instructions for each library:

```

```

With these libraries installed, you can proceed to with using Exip6!

<a name="Contributors"></a>
## Contributors

<p align="center">
    <a href="https://github.com/Th3Tr1ckst3r"><img src="https://avatars.githubusercontent.com/u/21149460?v=4" width=75 height=75></a>
</p>

I welcome you to contribute code to Exip6, and thank you for your contributions, feedback, and support.

# Disclaimer
Only use on systems, & servers you have explicit permission to. Your actions are your own.
