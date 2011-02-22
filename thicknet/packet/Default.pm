package thicknet::packet::Default;

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

=optional

# Uncomment this section if you want to track every session
# This code is a good starting point for your own
# thicknet module

    my $self = shift;
    my ($server,$client,$server_port,$client_port,$session);
    if ($self->{new}) {
        # New session
        # Figure out client / server
        # This will use lower port as server
        my $res = $self->{tcp}->{src_port} <=> $self->{tcp}->{dest_port};
        if ($res == -1) {
            $server = ip2hex($self->{ip}->{src_ip});
            $client = ip2hex($self->{ip}->{dest_ip});
            $server_port = $self->{tcp}->{src_port};
            $client_port = $self->{tcp}->{dest_port};
        }
        elsif ($res == 1) {
            $server = ip2hex($self->{ip}->{dest_ip});
            $client = ip2hex($self->{ip}->{src_ip});
            $server_port = $self->{tcp}->{dest_port};
            $client_port = $self->{tcp}->{src_port};
        }
        else {
            # Same port, just use the first packet
            $server = ip2hex($self->{ip}->{src_ip});
            $client = ip2hex($self->{ip}->{dest_ip});
            $server_port = $self->{tcp}->{src_port};
            $client_port = $self->{tcp}->{dest_port};
        }
        # Create session object
        $self->{sref}->{"$client:$client_port:$server:$server_port"} = thicknet::session::Session->new();
        $self->{session} = $self->{sref}->{"$client:$client_port:$server:$server_port"};
        $self->{session}->{server} = $server;
        $self->{session}->{client} = $client;
        $self->{session}->{client_port} = $client_port;
        $self->{session}->{server_port} = $server_port;
    }

=cut
}

1;