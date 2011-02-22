package thicknet::pcap::Pcap;

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

use Net::Pcap;

sub new {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self  = {};
    $self->{ip}       = undef;
    $self->{mac}      = undef;
    $self->{dev}      = undef;
    $self->{sref} = undef;
    $self->{filter}   = undef;
    bless ($self, $class);
    return $self;
}

sub ip {
    my $self = shift;
    if (@_) { $self->{ip} = shift }
    return $self->{ip};
}

sub mac {
    my $self = shift;
    if (@_) { $self->{mac} = shift }
    return $self->{mac};
}

sub dev {
    my $self = shift;
    if (@_) { $self->{dev} = shift }
    return $self->{dev};
}

sub filter {
    my $self = shift;
    if (@_) { $self->{filter} = shift }
    return $self->{filter};
}

sub sref {
	my $self = shift;
	if (@_) { $self->{sref} = shift }
	return $self->{sref};
}

sub init {
    my $self = shift;
    
	# Get net info 
	my ($address,$netmask,$err);
	if (Net::Pcap::lookupnet($self->{dev}, \$address, \$netmask, \$err)) {
	    die 'Unable to look up device information for ', $self->{dev}, ' - ', $err;
	}
	# Open device
	my $snaplen = 1600;
	my $promisc = 0;
	my $to_ms = 15;
	my $pcap = Net::Pcap::open_live($self->{dev}, $snaplen, $promisc, $to_ms, \$err);
	unless ($pcap) {
	    die "Error opening live: $err\n";
	}

	# Non-blocking mode offers dramatic speed increase but
	# don't set it on Windows due to high CPU utilization
	unless ($^O eq 'MSWin32') {
	        Net::Pcap::pcap_setnonblock($pcap, 1, \$err);
	}

	# Compile and set filter
	Net::Pcap::compile($pcap, \$filter, $self->{filter}, 1, $netmask) &&
	   die 'Unable to compile packet capture filter';
	Net::Pcap::setfilter($pcap, $filter) &&
	   die 'Unable to set packet capture filter';

    return $pcap;
   	
}

1;
