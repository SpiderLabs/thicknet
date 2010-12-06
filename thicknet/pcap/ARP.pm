package thicknet::pcap::ARP;

=header
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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
=cut

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(getmac);

use strict;
use warnings;
use Net::Pcap;
use Net::Libdnet::Route;
use thicknet::Util;
use AnyEvent;
use Data::Dumper;

my $arp = {};
my $mymac;
my $myip;
my $address;
my $netmask;
my $pcap;

my $dnet_route = new Net::Libdnet::Route;

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
    my $spa =       ip2hex($myip);        # Sender IP
    
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
	#print "REQUEST  ETHDST: $ethdst SHA: $sha SPA: $spa THA: $tha TPA: $tpa\n";
    Net::Pcap::sendpacket($pcap, $pkt);
}

sub getmac {
	my ($ip) = @_;
	#print "getmac: " . thicknet::Util::hex2ip($ip) . "\n";
	if ((hex($ip) & $netmask) == $address) {
		# It's local, is it already stored?
		if ($arp->{$ip}) {
			#print "returning ARP value\n";
			return ($arp->{$ip});
		}
		else {
			my $try = 0;
			#print "doing ARP retries\n";
			my $w;
			$w = AnyEvent->timer (after => 1, interval => 1, cb => sub {
				send_request($ip);
				if ($arp->{$ip}) {
					undef $w;
					return ($arp->{$ip});
				}
				$try++;
				if ($try == 3) { undef $w; return undef;}
			});
			#return undef;	
		}
	}
	else {
		# It's not local, do route lookup
		my $route = $dnet_route->get(thicknet::Util::hex2ip($ip));
		return getmac(thicknet::Util::ip2hex($route));
	}
}

sub process_packet {
	# if target hw is us, update arp table based on packet
	my ($user_data, $header, $pkt) = @_;
	
	# Data offsets
	my $os_srcmac = 6;
	my $os_dstmac = 0;
	my $os_arptype = 21;
	my $os_arpsmac = 22;
	my $os_arpsip = 28;
	my $os_arptmac = 32;
	my $os_arptip = 38;
	
	my $arptype = ord (substr($pkt, $os_arptype, 1));
	
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

		$arp->{$arpsip} = $arpsmac;
		#print Dumper $arp;
		#print "MAC: $arpsmac IP: $arpsip \n";
	}
}

sub init { 
	my %args = (
		dev		=> undef,
		myip    => undef,
		mymac	=> undef,
		@_
	);
	defined $args{dev} or die 'Required parameter "dev" not defined';
	defined $args{mymac} or die 'Required parameter "mymac" not defined';
	defined $args{myip} or die 'Required parameter "myip" not defined';
	
	my $dev = $args{dev};
	$mymac = $args{mymac};
	$myip = $args{myip};

	# Get net info 
	my $err;
	if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
	    die 'Unable to look up device information for ', $dev, ' - ', $err;
	}
	# Open device
	my $snaplen = 96;
	my $promisc = 0;
	my $to_ms = 15;
	$pcap = Net::Pcap::open_live($dev, $snaplen, $promisc, $to_ms, \$err);
	unless ($pcap) {
	    die "Error opening live: $err\n";
	}

	# Non-blocking mode offers dramatic speed increase but
	# don't set it on Windows due to high CPU utilization
	unless ($^O eq 'MSWin32') {
	        Net::Pcap::pcap_setnonblock($pcap, 1, \$err);
	}

	my $filter;
	# Compile and set filter
	my $filter_str = "arp and ether dst $mymac";
	Net::Pcap::compile($pcap, \$filter, $filter_str, 1, $netmask) &&
	   die 'Unable to compile packet capture filter';
	Net::Pcap::setfilter($pcap, $filter) &&
	   die 'Unable to set packet capture filter';

	# Timer is more cross-platform friendly
	# Look at doing select on pkt descriptor if you're just using Linux/BSD
	my $pcaploop = AnyEvent->timer (after => 0, interval => .001, cb => sub {
		Net::Pcap::pcap_dispatch($pcap, 1, \&process_packet, "user data");
		});

	return $pcaploop;
}

1;