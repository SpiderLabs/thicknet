package thicknet::packet::Packet;

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

use Exporter;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP;
use Data::HexDump;
use thicknet::Util;
use thicknet::session::Session;
use thicknet::pcap::ARP;

sub new {
    my ($pkt,$proto) = ($_[1],$_[0]);
    my $class = ref($proto) || $proto;
    my $self  = {};
    bless ($self, $class);
    $self->{pkt} = $pkt;
    $self->{eth} = NetPacket::Ethernet->decode($pkt);
    $self->{ip} = NetPacket::IP->decode($self->{eth}->{data});
	$self->{tcp} = NetPacket::TCP->decode($self->{ip}->{data});
	return $self;
}

sub sref {
    my $self = shift;
    if (@_) { $self->{sref} = shift }
    return $self->{sref};
}

sub session {
    my $self = shift;
    if (@_) { $self->{session} = shift }
    return $self->{session};
}

sub mymac {
    my $self = shift;
    if (@_) { $self->{mymac} = shift }
    return $self->{mymac};
}

sub myip {
    my $self = shift;
    if (@_) { $self->{myip} = shift }
    return $self->{myip};
}

sub pcaph {
    my $self = shift;
    if (@_) { $self->{pcaph} = shift }
    return $self->{pcaph};
}

sub preprocess {
    my $self = shift;
    
    my $src_ip      = ip2hex($self->{ip}->{src_ip});
    my $src_port    = $self->{tcp}->{src_port};
    my $dest_ip     = ip2hex($self->{ip}->{dest_ip});
    my $dest_port   = $self->{tcp}->{dest_port};
    
    # Determine whether it's a new packet
    # dir == 1 means server->client
    # dir == 0 means client->server
    my ($session);
    if ($self->{sref}->{"$src_ip:$src_port:$dest_ip:$dest_port"}) {
		$self->{session} = $self->{sref}->{"$src_ip:$src_port:$dest_ip:$dest_port"};
		$self->{dir} = 1;
		$self->{new} = 0;
	}
	elsif ($self->{sref}->{"$dest_ip:$dest_port:$src_ip:$src_port"}) {
	    $self->{session} = $self->{sref}->{"$dest_ip:$dest_port:$src_ip:$src_port"};
		$self->{dir} = 0;
		$self->{new} = 0;
	}
	else {
        $self->{new} = 1;
	}
	# Get data size to compute seq numbers
	#$self->{datalen} = $self->{ip}->{len} - ($self->{ip}->{hlen} * 4 + $self->{tcp}->{hlen} * 4);
	$self->{datalen} = length($self->{tcp}->{data});
	
	# Track sequence numbers of server / client

	unless ($self->{new}) {
	    # If going to client
	    if ($self->{dir}) {
	        # If we are blocking, we control client_seq
		    unless ($self->{session}->{block}) {
		        $self->{session}->{client_seq} = $self->{tcp}->{seqnum} + $self->{datalen}
		    }
	    }
	    # If going to server 
	    else {
		    $self->{session}->{server_seq} = $self->{tcp}->{seqnum} + $self->{datalen};
	    }
    }
}

sub postprocess {
    my $self = shift;
	
	# Track sequence numbers of server / client
	# If we are blocking, we control client_seq
	if ($self->{dir}) {
		unless ($self->{session}->{block}) {$self->{session}->{client_seq} = $self->{tcp}->{seqnum} + $self->{datalen}};
	} else {
		$self->{session}->{server_seq} = $self->{tcp}->{seqnum} + $self->{datalen};
	}
	
	# Check for examine flag
	if ($self->{session}->{examine}) {
	    # This weeds out most obnoxious keepalive spam on the console
	    if ($self->{datalen} > 5) {
	        my $string = $self->{ip}->{src_ip} . ":" . $self->{tcp}->{src_port} . " -> " . $self->{ip}->{dest_ip} . ":" . $self->{tcp}->{dest_port}  . " flags: " . $self->{tcp}->{flags} . " seq: " . $self->{tcp}->{seqnum} . " ack: " . $self->{tcp}->{acknum} . " len: " . $self->{ip}->{len} . "\n";
    	    $string = $string . HexDump $self->{tcp}->{data};
    	    print $string;
	    }
	}
	# Send it unless we're doing something special in process (block)
	unless ($self->{session}->{block}) {
	    $self->xmit();
    }
}

sub xmit {
    my $self = shift;
    # ARP resolve real MAC and send
    my $dstmac = getmac(ip2hex($self->{ip}->{dest_ip}));
	if ($dstmac) {
		substr($self->{pkt}, 0, 12, pack('H12H12', $dstmac, $self->{mymac}));
		Net::Pcap::pcap_sendpacket($self->{pcaph}, $self->{pkt});
	}
}

1;
