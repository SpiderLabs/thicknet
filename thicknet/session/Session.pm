package thicknet::session::Session;

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

use NetPacket::Ethernet qw(:strip);
use thicknet::Util;
use thicknet::pcap::ARP;

sub new {
	my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self  = {};
    bless ($self, $class);
    return $self;
}

sub client {
    my $self = shift;
    if (@_) { $self->{client} = shift }
    return $self->{client};
}

sub server {
    my $self = shift;
    if (@_) { $self->{server} = shift }
    return $self->{server};
}

sub client_port {
    my $self = shift;
    if (@_) { $self->{client_port} = shift }
    return $self->{client_port};
}

sub server_port {
    my $self = shift;
    if (@_) { $self->{server_port} = shift }
    return $self->{server_port};
}

sub examine {
    my $self = shift;
    if (@_) { $self->{examine} = shift }
    return $self->{examine};
}

sub ack {
	my $self = shift;
	
	# Get copy of sled
    my $ip_obj = NetPacket::IP->decode(eth_strip($self->{sled}->{pkt}));
    my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
    
    # Set Seq and Ack accordingly
	$tcp_obj->{seqnum} = $self->{client_seq};
	$tcp_obj->{acknum} = $self->{server_seq};
	
	# Set ACK
	$tcp_obj->{flags} = 0x10;
	
	# No payload
	$tcp_obj->{data} = '';
	
	# Encode for transmission	
	$ip_obj->{data} = $tcp_obj->encode($ip_obj);
	my $ip_pkt = $ip_obj->encode;
	
	# Make the ethernet frame, destined for server
	my $pkt = pack('H12H12n', getmac($self->{server}), $self->{mymac}, 0x0800) . $ip_pkt;
	Net::Pcap::pcap_sendpacket($self->{pcaph}, $pkt);
}	

# Stubs, return nonzero for error

sub inject {
	my ($self,$text) = @_;
	return "Injection not supported";
}

sub downgrade {
	my ($self,$text) = @_;
	return "Downgrade not supported";
}



1;