#!/usr/bin/perl -w

use utf8;
use v5.28;
use strict;
use URI::Escape;
use LWP::Simple;
use Getopt::Long;
use Term::ANSIColor;
use JSON::Parse ':all';
use experimental 'smartmatch';

$| = 1;
binmode STDOUT, ":utf8";

#console colors
my ($rd, $gr)  = (color('red'), color('green'));
my ($bld, $rst, $ndr) = (color('bold'), color('reset'), color('underline'));
my $ar  = $bld . "→" . $rst;

my $cidr;
GetOptions ("subnet=s" => \$cidr);

if (!defined $cidr){
  say($bld . "┌═══════════┐" .$rst . "\n".
      $bld . "│  LANscan  │" .$rst . "\n".
      $bld . "└═══════════┘" .$rst . $rd . "...v1.0" . $rst.
      "\n" . '-' x 38 .
      "\n" . "$0 -s/-subnet <CIDR>\n" .
      $bld . "Example:" . $rst . " $0 -s 192.168.10.0/24" .
      "\n" . '═' x 38
      );
  exit 1;
}

# check if argument is a valid CIDR
die "$rd [-] Invalid CIDR argument. $rst" unless ($cidr =~ m/(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))/);

my $macvendorAPI = "https://macvendors.co/api/";
my $mac_ptrn = "(?:[0-9a-f]{2}[.:-]?){5}(?:[0-9a-f]{2})";
my $ip_ptrn = qr{\b(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.
                   (?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.
                   (?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.
                   (?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b}x;

sub gateway {
  if ($^O eq "darwin") {
    `route -n get default | grep gateway` =~ /($ip_ptrn)/;
    return $1;
  } elsif ($^O eq "MSWin32") {
    `ipconfig | findstr /i "Gateway"` =~ /($ip_ptrn)/;
    return $1;
  } else { # linux
    `ip route | grep default` =~ /($ip_ptrn)/;
    return $1;
  }
}

sub getCompany {
  my $json_obj = parse_json ($_[0]);
  if (exists $json_obj->{'result'}{'company'}){
    return $json_obj->{'result'}{'company'}
  } else {
    return $rd . "Unknown" . $rst;
  }
}

sub macvendor {
  my $vendor = get($macvendorAPI . uri_escape($_[0]) . "/json");
  return getCompany($vendor);
}

# UN-PRIVILEGED ARP-scan with nmap
my @ips = ();
open(my $nmap, '-|', "nmap -sn $cidr") or die $!;
while (<$nmap>) {
  if (/($ip_ptrn)/) {
    push @ips, $1;
  }
}
close $nmap;

# get the gateway...
my $gateway = &gateway();

# Dump the ARP-cache and get the vendors...
foreach my $line (`arp -a`){
  chomp $line;
  if ($line =~ m/.*($ip_ptrn).*($mac_ptrn).*/gim) {
    if ($2 !~ m/[ff:]{5}[ff]/i) {
      if ( $1 ~~ @ips ) {
        if ($1 eq $gateway) {
          say($ndr . "$1" . $rst . " $ar $2 $ar " . &macvendor($2) . " $ar $gr active $rst"."(".$rd."gateway".$rst.")");
        } else {
          say($ndr . "$1" . $rst . " $ar $2 $ar " . &macvendor($2) . " $ar $gr active $rst");
        }
      } else {
        say($ndr . "$1" . $rst . " $ar $2 $ar " . &macvendor($2));
      }
    }
  }
}