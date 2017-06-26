#!/usr/bin/perl -T

use strict;
use warnings;

## Calomel.org .:. https://calomel.org
##   name     : web_server_abuse_detection.pl
##   version  : 0.04

# description: this script will watch the web server logs (like Apache or Nginx) and
#  count the number of http error codes an ip has triggered. At a user defined amount
#  of errors we can execute a action to block the ip using our firewall software.

## which log file do you want to watch?
  my $log = "/var/log/nginx/access.log";

## how many errors can an ip address trigger before we block them?
  my $errors_block = 10;

## how many seconds before an unseen ip is considered old and removed from the hash?
  my $expire_time = 7200;

## how many error log lines before we trigger blocking abusive ips and clean up
## of old ips in the hash? make sure this value is greater than $errors_block above.
  my $cleanup_time = 10;

## do you want to debug the scripts output ? on=1 and off=0
  my $debug_mode = 1;

## clear the environment and set our path
  $ENV{ENV} ="";
  $ENV{PATH} = "/bin:/usr/bin:/usr/local/bin";

## declare some internal variables and the hash of abusive ip addresses
  my ( $ip, $errors, $time, $newtime, $newerrors );
  my $trigger_count=1;
  my %abusive_ips = ();

## open the log file. we are using the system binary tail which is smart enough
## to follow rotating logs. We could have used File::Tail, but tail is easier.
  open(LOG,"/usr/bin/tail -F $log |") || die "ERROR: could not open log file.\n";

  while(<LOG>) {
       ## process the log line if it contains one of these error codes 
       if ($_ =~ m/( 301 | 302 | 303 | 307 | 400 | 401 | 402 | 403 | 404 | 405 | 406 | 408 | 409 | 410 | 411 | 412 | 413 | 414 | 415 | 416 | 444 | 494 | 495 | 496 | 497 | 500 | 501 | 502 | 503 | 504 | 507 )/)
         {

         ## Whitelisted ips. This is where you can whitelist ips that cause errors,
         ## but you do NOT want them to be blocked. Googlebot at 66.249/16 is a good
         ## example. We also whitelisted the private subnet 192.168/16 so web
         ## developers inside the firewall can test and never be blocked. 
         if ($_ !~ m/^(66\.249\.|192\.168\.)/)
         {

         ## extract the ip address from the log line and get the current unix time
          $time = time();
          $ip = (split ' ')[0];

         ## if an ip address has never been seen before we need
         ## to initialize the errors value to avoid warning messages.
          $abusive_ips{ $ip }{ 'errors' } = 0 if not defined $abusive_ips{ $ip }{ 'errors' };

         ## increment the error counter and update the time stamp.
          $abusive_ips{ $ip }{ 'errors' } = $abusive_ips{ $ip }->{ 'errors' } + 1;
          $abusive_ips{ $ip }{ 'time' } = $time;

         ## DEBUG: show detailed output
         if ( $debug_mode == 1 ) {
           $newerrors  = $abusive_ips{ $ip }->{ 'errors' };
           $newtime = $abusive_ips{ $ip }->{ 'time' };
           print "unix_time:  $newtime, errors:  $newerrors, ip:  $ip, cleanup_time: $trigger_count\n";
         }

         ## if an ip has triggered the $errors_block value we block them
          if ($abusive_ips{ $ip }->{ 'errors' } >= $errors_block ) {

             ## DEBUG: show detailed output
             if ( $debug_mode == 1 ) {
               print "ABUSIVE IP! unix_time:  $newtime, errors:  $newerrors, ip:  $ip, cleanup_time: $trigger_count\n";
             }

             ## Untaint the ip variable for use by the following external system() calls
             my $ip_ext = "$1" if ($ip =~ m/^([0-9\.]+)$/ or die "\nError: Illegal characters in ip\n\n" );

             ## USER EDIT: this is the system call you will set to block the abuser. You can add the command
             ##  line you want to execute on the ip address of the abuser. For example, we are using logger to
             ##  echo the line out to /var/log/messages and then we are adding the offending ip address to our
             ##  FreeBSD Pf table which we have setup to block ips at Pf firewall.
             system("/usr/bin/logger", "$ip_ext", "is", "abusive,", "sent", "to", "BLOCKTEMP");
             system("/sbin/pfctl", "-t", "BLOCKTEMP", "-T", "add", "$ip_ext");

             ## after the ip is blocked it does need to be in the hash anymore
             delete($abusive_ips{ $ip });
          }

         ## increment the trigger counter which is used for the following clean up function. 
          $trigger_count++;

         ## clean up function: when the trigger counter reaches the $cleanup_time we
         ## remove any old hash entries from the $abusive_ips hash
          if ($trigger_count >= $cleanup_time) {
             my $time_current =  time();

             ## DEBUG: show detailed output
             if ( $debug_mode == 1 ) {
               print "  Clean up... expire: $expire_time, pre-size of hash:  " . keys( %abusive_ips ) . ".\n";
             }

              ## clean up ip addresses we have not seen in a long time
               while (($ip, $time) = each(%abusive_ips)){

               ## DEBUG: show detailed output
               if ( $debug_mode == 1 ) {
                 my $total_time = $time_current - $abusive_ips{ $ip }->{ 'time' };
                 print "    ip: $ip, seconds_last_seen: $total_time, errors:  $abusive_ips{ $ip }->{ 'errors' }\n";
               }

                  if ( ($time_current - $abusive_ips{ $ip }->{ 'time' } ) >= $expire_time) {
                       delete($abusive_ips{ $ip });
                  }
               }

            ## DEBUG: show detailed output
            if ( $debug_mode == 1 ) {
               print "  Clean up... expire: $expire_time, post-size of hash:  " . keys( %abusive_ips ) . ".\n";
             }

             ## reset the trigger counter
              $trigger_count = 1;
          }
         }
       }
  }
#### EOF ####
