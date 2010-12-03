package thicknet::pcap::Default;

=header
    thicknet - A tool to manipulate and take control of TCP sessions
	Copyright (C) 2010 Steve Ocepek and Wendel G. Henrique,
	Trustwave SpiderLabs
 
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
use thicknet::pcap::ARP;
use Net::Pcap;

my $pcap;
my $mymac;
my $myip;
my $address;
my $netmask;

# Data offsets
my $os_srcip = 26;
my $os_dstip = 30;
my $os_srcpt = 34;
my $os_dstpt = 36;
my $os_srcmac = 6;
my $os_dstmac = 0;
my $os_flags = 46;
my $os_seq = 38;
my $os_ack = 42;

sub process_packet {
    # By default, just pass everything as fast as possible
	# Create other pcap modules to do specific things to other protocols
	my ($user_data, $header, $pkt) = @_;
	
	my $dstip = sprintf("%02x%02x%02x%02x",
		ord (substr($pkt, $os_dstip, 1)),
		ord (substr($pkt, $os_dstip+1, 1)),
		ord (substr($pkt, $os_dstip+2, 1)),
		ord (substr($pkt, $os_dstip+3, 1)));
	
	my $dstmac = getmac($dstip);
	if ($dstmac) {
		substr($pkt, 0, 12, pack('H12H12', $dstmac, $mymac));
		Net::Pcap::pcap_sendpacket($pcap, $pkt);
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
	my $snaplen = 1600;
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
	# This filter is kind of awful, it is very specific to the other modules in use
	# Acts as a "catch-all" for stuff not already being processed
	# Is it possible to learn raw bpf format and figure this against a shared value?
	my $filter_str = "((tcp and not port 1521) or udp or icmp) and ether dst $mymac and ip dst not $myip";
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