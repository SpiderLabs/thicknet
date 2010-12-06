thicknet 
Released at Black Hat Europe 2010
Steve Ocepek <socepek@trustwave.com>
Wendel G. Henrique <whenrique@trustwave.com>
http://www.spiderlabs.com

INTRODUCTION
============

thicknet is a TCP session manipulation and take-over tool. The tool is
initially aimed at downgrading Oracle sessions and issuing SQL queries
using an already-established session. This is an early proof-of-concept,
version, but the basic concepts are there to write modules and do MITM
against a variety of protocols.

Cool stuff includes:
o True L2 packet forwarding
o Detection of already-running sessions
o Ability to takeover Oracle sessions and issue commands
o Modular implementation


REQUIREMENTS
============

Perl 5.8+

Perl Modules / libraries:
Net::Pcap
Net::IP
Net::Libdnet
NetPacket::IP
NetPacket::TCP
NetPacket::Ethernet
Data::HexDump
AnyEvent
EV


USAGE
=====

perl thicknet.pl [interface]

If interface is not supplied, a prompt will appear to choose one. Ensure that
your user account has root/admin privileges necessary to sniff packets.

The program console is contextual, use '?' to obtain a list of commands at
each level. When using injection, do not add a semicolon (;) to the end of
your SQL statements -- this is not supported by the wire-side protocol.

thicknet will automatically forward all packets not destined for the
specified interface's IP - ENSURE THAT IP FORWARDING IS DISABLED.
Use vamp.pl (included in this package) to initiate ARP poisoning and redirect 
packets to your own host. 

To enable Oracle protocol downgrade, use the 'd' command. Note that this may
cause disconnects for some new sessions, depending on client version. The
username and 8i hash will be printed to the screen for each successful
downgrade.


COPYRIGHT
=========

thicknet - A tool to manipulate and take control of TCP sessions
Created by Steve Ocepek and Wendel G. Henrique
Copyright (C) 2010 Trustwave Holdings, Inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
