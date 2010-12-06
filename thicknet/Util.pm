package thicknet::Util;

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
@EXPORT = qw(session_hex2ip session_ip2hex ip2hex hex2ip getif);

use strict;
use warnings;
use Net::Libdnet::Intf;
use Net::IP;

sub session_hex2ip {
	my ($in) = @_;
	my @hex = split(/:/, $in);
	my $str = hex2ip($hex[0]);
	$str = $str . ":" . $hex[1] . ":";
	$str = $str . hex2ip($hex[2]);
	$str = $str . ":" . $hex[3];
	return $str;
}

sub session_ip2hex {
	my ($in) = @_;
	my @ip = split(/:/, $in);
	my $str = ip2hex($ip[0]) . ":" . $ip[1] . ":" . ip2hex($ip[2]) . ":" . $ip[3];
	return $str;
}

sub ip2hex {
	my ($in) = @_;
	my @ip = split(/\./, $in);
	my $hex = sprintf("%02x%02x%02x%02x", $ip[0], $ip[1], $ip[2], $ip[3]);
	return $hex;
}

sub hex2ip {
	my ($in) = @_;
	my $str = hex(substr($in,0,2)) . "." . hex(substr($in,2,2)) . "." . hex(substr($in,4,2)) . "." . hex(substr($in,6,2));
	return $str;
}

sub getif {
	my ($dev) = @_;
	# Use dnet to get interface info
	my $intf = new Net::Libdnet::Intf;
	my $eth = $intf->get($dev);
	my $myip = $eth->ip;
	my $myhexip = ip2hex($eth->ip);
	my $mymac = $eth->linkAddr;
	$mymac =~ s/://g;
	return ($mymac, $myip, $myhexip);
}

1;
