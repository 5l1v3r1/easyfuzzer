#!/usr/bin/perl
#
#

$long_help = 0;

sub shorthelp {
print STDOUT <<EOH;
easyfuzzer $version by Marc Heuse <mh\@mh-sec.de>
easyfuzzer.pl [-XsunNoOtlSTM -L file -Z trig:file -K file -w time -W time -f no -c no -Y ext] FILE [TARGET] [PORT]
Modes:
    default   single network connect+request fuzzing
    -Y ext    file fuzzing, creates fuzz files with extension EXT  (enables -O)
Options:
    -s        use SSL (use -K FILE for SSL client cert)
    -o / -O   do not create files / do not print requests/responses to screen
    -S        smaller fuzzing set, good for -Y
    -t / -T   target is unix / target is Windows (for traversal attacks)
    -D        calculate timing difference between sending and receiving
EOH
if ($long_help) {
print STDOUT <<EOH;
    -u        use UDP
    -n / -N   ensure \\r\\n lines / ensure \\n lines             (-X enables -n)
    -e        URL encode spaces in fuzz data                  (-X enables this)
    -l        learn cookies (-L file reads/writes cookiejar)  (-X enables this)
    -w time / -W time  connect / response timeout in seconds (default: 30/15)
    -Z requestfile:trigtext  when trigtext is found in reply, requestfile
                is sent to the target (and cookies learned if -l)
    -P responsescript analyse responses, must take response file as cmdline opt
    -f number fuzz counter to start fuzzing with (first __FUZZ__ is 0)
    -c number fuzz counter index to start (__FUZZ__{a#b#c} -> a = 0, b = 1 ...)
    -C file   CSV result output
EOH
} else {
print STDOUT "    -X        enable web enhanced fuzzing (encoding, cookie learning, etc.)\n";
print STDOUT "    -h        more help, displays more options\n";
}
print STDOUT <<EOH;
Mandatory options:
  FILE      the file to use for fuzzing
  TARGET    the target to send the data to (ip or dns)              (if not -Y)
  PORT      the target port to send the data to (if no Y,-X defaults to 80/443)
Fuzz File Help:
    -F        give a help on the FILE fuzzing format
easyfuzzer is an easy fuzzer for anything, http, xml, binary, etc.
Use the -X switch for web fuzzing which does autofixing.
EOH
if ($long_help) {
print STDOUT <<EOH;
Use the -F option to get an extra help screen on the FILE fuzzing format.
Cookiejar format: one cookie per line, e.g. FOO=1234\\nBAR=5678\\n
EOH
}
print STDOUT "Use easyfuzzer_analysis.sh FILE after its finished for easy output analysis.\n";
  exit 0;
}
sub longhelp { print STDOUT <<EOH;
# easyfuzzer $version by Marc Heuse <mh\@mh-sec.de>
#
# Fast and easy fuzzing of everything, binary, http, xml - it doesnt matter.
#
# Output:
#    Informational output is sent to STDOUT
#    Request and response data is sent to STDERR (and to the target of course)
#    Request and response data is written to fuzzfile.REQUESTNO.req/resp, so
#     it can be easily replayed.
#
# Command line options:
#    easyfuzzer.pl [-options] FILE [TARGET] [PORT]
#      [-options] - type "easyfuzzer.pl -h" to see the options
#      FILE   - fuzzing file (see below)
#          if the filename ends with -127.0.0.1.8080 (and contains only one
#          '-') then IP/TARGET and PORT may be omitted.
#      TARGET - target (ip or dns) to send the fuzzed data to
#      PORT   - TCP port to send the fuzzed data to
#
# File options:
#    FILE can be any file. it will be send plain to the target.
#    occurances of __FUZZ__{} will be replaced with their respective fuzzing
#    values. To fuzz several things, the '#' sign is used as a delimiter.
#    If the file contains "AAAAAAAA", this will be send to the target.
#    If the file contains "AAAA__FUZZ__{123#CCC#___}BBBB", the following
#    content will be send: first "AAAA123BBBB", then "AAAACCCBBBB" and finally
#    "AAAA___BBBB"
#
#    If more then one __FUZZER__ statement is in the file, one after another
#    is fuzzed, where the first value of each is the default.
#    Example: "AAA__FUZZ__{1#2}BBB__FUZZ__{D#E}CCC results in:
#    "AAA1BBBDCCC", "AAA2BBBDCCC", "AAA1BBBECCC"
#    __FUZZ__{#123} means that the default is nothing/empty string, and
#    the fuzzed value is 123, e.g.: "AAA__FUZZ__{#2}BBB__FUZZ__{D#E}CCC ->
#    "AAABBBDCCC", "AAA2BBBDCCC", "AAABBBECCC"
#
#    The following special keywords are known by __FUZZ__:
#      _SQL_  - some sql injection values
#      _XSS_  - some XSS values
#      _NUM_  - some integer overflow values (-1, 0, 127, 255, 256, 32767, ...)
#      _BOF_  - some buffer overflow values (24,264,1100,11000,110000 x "A")
#      _EXEC_ - some code execs (|, ;, php passthrough, SSI, etc.)
#      _TRAVERSAL_ - some path traversal attacks (/../../../etc/passwd etc.)
#      _FORMATSTRING_ - format string stuff (many %n)
#      _BINARY_ - all binary values from 0 to 255 (not used with _ALL_)
#      NUM:number      - "number" times "9", e.g. NUM:4 = "9999"
#      COUNT:from-to   - count from "from" to "to" (no negative numbers)
#      BOF:number      - "number" times "A", e.g. BOF:5 = "AAAAA"
#      BIN:number      - print a binary character of a digit number (no hex!)
#      FILE:filename   - every line in the file is used as an input
#      EXEC:statement  - executes the command, all output is used as statement
#      REXEC:statement - same as EXEC, however it is executed every time
#      PERL:statement  - execute the perl statement
#      RPERL:statement - same es PERL, however executed everytime used.
#      COPY:number     - copy the same statement here as in __FUZZ__ count
#                      "number". (see example below). REXEC/RPERL statements
#                      will be re-executed!
#      _DELETELINE_    - deletes the line (including \\r\\n)
#      _ALL_  - this is _SQL_, _XSS_, _NUM_, _BOF_, _EXEC_, _TRAVERSAL_, and
#               an empty statement. all-in-one :-) (but not: _BINARY_)
#
#    Examples: "AAA__FUZZ__{default#_XSS_}BBB__FUZZ__{COPY:0}CCC"
#    results in:
#      "AAAdefaultBBBdefaultCCC"
#      "AAA'"><script>alert("A")</script><"'BBB'"><script>alert("A")</scr..."
#      "AAA'"><h1>XSS<"'BBB'"><h1>XSS<"'CCC"
#
#    A special value is _COUNTER_ and is replaced everytime with a counter
#    which is the current request counter. first request: _COUNTER_ = 0,
#    second request: _COUNTER_ = 1, etc.
#    _COUNTER_ is only valid in within __FUZZ__{} statements.
#    Another special value is _HOST_ and _PORT_, which can too only be used
#    within __FUZZ__ statements, are are the target hosts and port values
#    from the command line.
#
#    Another special value is __CONTENTLENGTH__ and is for http post requests.
#    It is always the last value being replaced prior sending the request.
#    And then there is __CONTENTLENGTH-1__ which is one less.
#    Usage: 
#       "POST /cgi-bin/login.cgi HTTP/1.0
#        Content-Length: __CONTENTLENGTH__
#
#        login=__FUZZ__{user#_XSS_}&pass=__FUZZ__{pw#_SQL}&opt=submit"
#
#
#    NOTE: "#" and "}" are reserved characters within __FUZZ__{} statements!
#
#    Have fun!
#
EOH
  exit 0;
}

use IO::Socket;
use IO::Select;
use Getopt::Std;
use IO::Socket::IP;
#use Data::Dumper;	# for debugging
no warnings 'deprecated';

$dir = $0;
$dir =~ s!/?[^/]*/*$!!;

# Global Vars
$version = "v3.6";
$web = 0;
$use_ssl = 0;
$is_win = 1;
$is_unix = 1;
$encode = 0;
$msdos = 0;
$request_no = 0;
$connect_timeout = 10;
$response_timeout = 15;
$use_udp = 0;
$do_csv = 0;
$do_time = 0;
$cert = "";
$start_i = 0;
$start_j = 0;
$print_file = 1;
$print_stderr = 1;
$filefuzz = 0;
$trigger = 0;
$trigger_file = "";
$trigger_text = "";
$trigger_data = "";
$learn_cookies = 0;
$use_cookiejar = 0;
$response = "";
$postprocess = "";
$csvline = "";
$proxy = "";
$smallfuzz = 0;
$ext = "-req";
$sep = ".";

# Getopt
getopts("senNtTXuoOw:W:K:f:c:hp:P:FC:Z:ML:lY:SD", \%opt);
if (defined $opt{s}) {
    $use_ssl = 1;
    require IO::Socket::SSL;
}
if (defined $opt{e}) {
    $encode = 1;
}
if (defined $opt{D}) {
    $do_time = 1;
    use Time::HiRes qw(gettimeofday tv_interval);
}
if (defined $opt{S}) {
    $smallfuzz = 1;
}
if (defined $opt{X}) {
    $learn_cookies = 1;  
    $msdos = 1;
    $encode = 1;
    $web = 1;
}
if (defined $opt{N}) {
    $msdos = -1;
}
if (defined $opt{n}) {
    $msdos = 1;
}
if (defined $opt{u}) {
    $use_udp = 1;
}
if (defined $opt{L}) {
    $learn_cookies = 1;
    $use_cookiejar = 1;
    $cookiejar_file = $opt{L};
}
if (defined $opt{Y}) {
    $filefuzz = 1;
    $ext = $opt{Y};
    $ext =~ s/^\.//;
    $ext = "." . $ext;
    $sep = "-";
    $print_stderr = 0;
}
if (defined $opt{l}) {
    $learn_cookies = 1;
}
if (defined $opt{Z}) {
    $trigger = 1;
    ($trigger_file,$trigger_text) = split(/:/, $opt{Z}, 2);
    ($foo1, $foo2, $trigger_data) = readfile($file);    
}
if (defined $opt{p}) {
    $proxy = $opt{p};
}
if (defined $opt{W}) {
    $response_timeout = $opt{W};
}
if (defined $opt{w}) {
    $connect_timeout = $opt{w};
}
if (defined $opt{K}) {
    $cert = $opt{K};
    if ($use_ssl == 0) {
      $use_ssl = 1;
      require IO::Socket::SSL;
    }
}
if (defined $opt{f}) {
    $start_i = $opt{f};
}
if (defined $opt{c}) {
    $start_j = $opt{c};
}
if (defined $opt{o}) {
    $print_file = 0;
}
if (defined $opt{O}) {
    $print_stderr = 0;
}
if (defined $opt{t}) {
    $is_win = 0;
}
if (defined $opt{T}) {
    $is_unix = 0;
}
if (defined $opt{F}) {
    longhelp;
}
if (defined $opt{h}) {
    $long_help=1;
    shorthelp;
}
if (defined $opt{P}) {
    $postprocess = $opt{P};
}
if (defined $opt{C}) {
    $do_csv = 1;
    $csvfile = $opt{C};
}

$maxtimeout = $connect_timeout + $response_timeout;
$maxretrycount = 3;

# XXX TODO: 
# __SEND__{} option
# config file for fuzz statements and response analysis

# Local Vars
my $file = shift;
$my_ip = shift;
$my_port = shift;
my $new_request;
my $start = $start_j;
my $replaced;
my $bla;
my $blubb;
my $data;
my $execute;
my $tmparr;
$trigger = 0;

if ($file eq '') { print "Error: no filename given!\n\n"; shorthelp; }

$SIG{'PIPE'} =sub {
  print STDOUT "Broken pipe, could not send request!\n"; 
  print FOUT "Broken pipe, could not send request!\n"; 
  return 0; 
};

my ($ip, $port, $orig_request) = readfile($file);

if ($learn_cookies == 1) {
  ($orig_request, $cooks) = &readcookies($orig_request);
  @cookiejar = split (/;/, $cooks);
#for ($i = 0; $i <= $#cookiejar; $i++) { print "Initial Jar $i: $cookiejar[$i]\n";}
}

if ($my_ip ne '') { $ip = $my_ip; }
if ($my_port ne '') { $port = $my_port; }
if ($port == 0 && $web == 1) {
  if ($use_ssl == 1) {
    $port = 443;
  } else {
    $port = 80;
  }
}

if ($ip eq "" && $web == 1) {
  $ip = $orig_request;
  if ($ip =~ m/\nSOAPAction:/is) {
    $ip =~ s/.*\nSOAPAction://is;
    $ip =~ s/[\r\n].*//s;
    $ip =~ s/[ \"]//g;
    if ($use_ssl == 0 && $ip =~ m/https:/) {
      $use_ssl = 1;
      require IO::Socket::SSL;
      $port = 443;
    } else {
      $port = 80;
    }
    $ip =~ s|.*://||;
    if ($ip =~ m/:[0-9][0-9]*\//) {
      $port = $ip;
      $port =~ s|/.*||;
      $port =~ s/.*://;
    }
    $ip =~ s|[:/].*||;
  } else {
    $ip =~ s/.*\nHost://is;
    $ip =~ s/[\r\n].*//s;
    $ip =~ s/ //g;
  }
}

if ($use_ssl == 1) {
  $proto = "https";
} else {
  $proto = "http";
}

if ($proxy eq "") {
  $proxyhost = "";
  $proxyport = "";
  $proxyauth = "";
} else {
  $proxyssl = 1		if ($proxy =~ m/^https:/i);
  $tmpproxy = $proxy;
  $tmpproxy =~ s/^[a-zA-Z]*:\/\///;
  $tmpproxy =~ s/\/.*//;
  if ($proxy =~ m/@/) {
    require MIME::Base64;
    $proxyauthtmp = $tmpproxy;
    $tmpproxy =~ s/.*@//;
    $proxyauthtmp =~ s/@.*//;
    $proxyauth = MIME::Base64::encode($proxyauthtmp);
    chomp($proxyauth);
  }
  $proxyhost = $tmpproxy;
  $proxyhost =~ s/:.*//;
  if ($tmpproxy =~ m/:/) {
    $proxyport = $tmpproxy;
    $proxyport =~ s/.*://;
  } else {
    $proxyport = 80;
  }
  print "DEBUG: proxyhost: $proxyhost, proxyport: $proxyport, auth: $proxyauth\n"		if ($debug);
}

if ($filefuzz == 0 && ($ip eq '' || $port eq '' || $port < 1 || $port > 65535)) { die "Error: no valid ip and/or port ($ip:$port)\n"; };

my @fuzzarray;
my $replace = $orig_request;

$request_type = "";
if ($web == 1) {
  $request_type = "xml"		if ($orig_request =~ m/Content-type:.*[ b\/]xml/is);
  $request_type = "json"	if ($orig_request =~ m/^Content-Type: .*json/is);
  $request_type = "xml"		if ($orig_request =~ m/<\?xml version=/si);
  $request_type = "json"	if ($orig_request =~ m/\n\n{\"/s || $orig_request =~ m/\n\r\n{\"/s);
  print STDOUT "Autodetected $request_type - will perform encoding of fuzz strings\n"	if ($request_type ne "");
}
if ($proxy ne "" && $orig_request =~ m#HTTP/#) {
#  print "JA!\n";
  $orig_request =~ s/ / $proto:\/\/$ip:$port/;
#  print "$orig_request";
#  exit;
}

if ($replace =~ m/__FUZZ__{}/sg) {
  print STDOUT "Warning: empty __FUZZ__{} statement found, ignored\n";
  $replace =~ s/__FUZZ__{}//gs;
  $orig_request = $replace;
}

my @msgparts = split (/__FUZZ__{.*?}/, $orig_request);
my $parts = $#msgparts;

my @replacers = ($replace =~ m/__FUZZ__{.*?}/g);
my $placers = $#replacers;
for (my $i = 0; $i <= $placers; $i++) {
  $replacers[$i] =~ s/__FUZZ__{//;
  $replacers[$i] =~ s/}//;
  my @arr;
  my @info;
  @arr = fuzzer($replacers[$i]);
  push @fuzzarray, \@arr;
#  print Dumper(\@fuzzarray);
}
# If NO __FUZZ__ statement is found, we still want to send the file, first
# because it is a good netcat replacement this way, and 2nd for the
# __CONTENTLENGTH__ and especially -X intelligence.
if ($#fuzzarray == -1) {
  push @bla, "";
  $fuzzarray[0] = \@bla;
}
# Same the other way around
if ($#msgparts == -1) {
  push @msgparts, "";
}

my $ccstring;
my $info;
my $this_info;
my $rex;

if ($print_file == 1) {
  open(FOUT, " > $file.out")	|| die ("creating file $file.out");
  select FOUT; $|=1;
} else {
  open(FOUT, " > /dev/null");
}
if ($do_csv == 1) {
  open(FCSV, " > $csvfile")	|| die ("creating file $csvfile");
  select FCSV; $|=1;
} else {
  open(FCSV, " > /dev/null");
}
print FCSV "IP~PORT~HTTP_or_HTTPS~FUZZARRAY_NUMBER_0~FUZZARRAY_CURRENT~FUZZENTRY_NUMBER_0~FUZZENTRY_CURRENT~REQUEST_NUMBER_0~REQUEST_FILE~RESPONSE_FILE~FUZZENTRY_STRING~FUZZINFO_STRING~REQUEST_STRING~RESPONSE_STRING~RESULTS_STRING\n";

select STDERR; $|=1;
select STDOUT; $|=1;

for (my $i = $start_i; $i <= $#fuzzarray; $i++) {
  $bla = $fuzzarray[$i];
  for (my $j = $start; $j <= $#$bla; $j++) {
    $new_request = $msgparts[0];
    $my_info = "";
# ay, index $j of $#$bla, $my_info)\n";
    for (my $k = 0; $k <= $#msgparts; $k++) {
      $blubb = $fuzzarray[$k];
      if ($k != $i) {
        $ccstring = $$blubb[0];
      } else {
        $ccstring = $$blubb[$j];
      }
      ($info, $rex, $data) = split('#;Y', $ccstring);
      if ($k == $i) {
        $fuzzstring = $data;
      }
      if ($k == $i && $j > 0) {
        $my_info = $info;
        $therex = $rex;
        $theinfo = $info;
      }
      # Check for COPY
      if ($data =~ m/^COPY:/i) {
        $execute = $data;
        $execute =~ s/^COPY://i;
        $tmparr = $fuzzarray[$execute];
        if ($execute != $i) {
          $data = $$tmparr[0];
        } else {
          $data = $$tmparr[$j];
        }
        ($info, $rex, $newdata) = split('#;Y', $data);
        $data = $newdata;
      }
      # Replace _COUNTER_
      if ($data =~ m/_COUNTER_/) {
        $data =~ s/_COUNTER_/$request_no/g;
      }
      if ($data =~ m/_HOST_/) {
        $data =~ s/_HOST_/$ip/g;
      }
      if ($data =~ m/_PORT_/) {
        $data =~ s/_PORT_/$port/g;
      }
      # Check for REXEC/RPERL (COPY may result in another REXEC/RPERL !)
      if ($data =~ m/^REXEC:/i) {
        $execute = $data;
        $execute =~ s/^REXEC://i;
        {
	  local $/= undef;
          open(EX, "$execute | ");
          $data = <EX>;
          close(EX);
        }
      } elsif ($data =~ m/^RPERL:/i) {
        $execute = $data;
        $execute =~ s/^RPERL://i;
        $data = eval($execute);
      }
      if ($encode == 1) {
        $data =~ s/%/%25/gs;
        $data =~ s/ /%20/gs;
        $data =~ s/\t/%09/gs;
        $data =~ s/\x0/%00/gs;
      }
      $new_request = $new_request . $data;
      $new_request = $new_request . $msgparts[$k + 1];
    }
    $new_request =~ s/.*?_DELETELINE_.*?\n//g;

    if ($use_cookiejar) {
      # we expect that the cookiejar file is more up2date
      ($foo1, $foo2, $foo3) = readfile($cookiejar_file);
      $foo3 =~ s/[\r ]//gs;
      my @cookiejartmp = split( /\n/, $foo3);
      for (my $i = 0; $i <= $#cookiejartmp; $i++) {
        my $cname = $cookiejartmp[$i];
        $cname =~ s/=.*/=/;
        my $found = 0;
        for (my $j = 0; $j <= $#cookiejar; $j++) {
          if ($cookiejar[$j] =~ m/^$cname/) {
            $found = 1;
            $cookiejar[$j] = $cookiejartmp[$i];
          }
        }
        if ($found == 0) {
          push @cookiejar, $cookiejartmp[$i];
        }
      } 
      undef(@cookiejartmp);
    }
    if ($learn_cookies == 1) {
      my $tmpcooks = "";
      if ($#cookiejar >= 0) {
#print "INSERTING JAR:  $#cookiejar\n";
        for (my $i = 0; $i <= $#cookiejar; $i++) {
          $cookiefoo = $cookiejar[$i];
          $cookiefoo =~ s/.*=//;
          if ($cookiejar[$i] =~ m/=/ && length($cookiejar[$i]) > 0 && length($cookiefoo) > 0) {
            $tmpcooks = $tmpcooks . "Cookie: $cookiejar[$i]\r\n";
#print "INSERTING JAR $i $cookiejar[$i]\n";
          }
#else { print "SKIPPING JAR $i $cookiejar[$i]\n" ; }
        }
      }
      $new_request =~ s/\Q{__COOKIES__}\E/$tmpcooks/s;
    }
    if ($msdos != 0) {
      $new_request =~ s/\r//g;
    }
    if ($web == 1) {
      if ($new_request =~ m/^GET/) {
        $new_request =~ s/\n\n.*/\n/gs;
        $new_request .= "\n";
        if (! $new_request =~ m/\n\n/gs) {
          print STDOUT "[FIX] Autofixed finnishing line-end for GET request\n";
          $new_request .= "\n";
        }
      }
    }
    if ($msdos == 1) {
      $new_request =~ s/\n/\r\n/g;
    }
    if ($new_request =~ m/__CONTENTLENGTH__/g) {
      my $len;
      my ($head, $bod) = split('\r?\n\r?\n', $new_request, 2);
      $len = length($bod);
      $new_request =~ s/__CONTENTLENGTH__/$len/g;
    } elsif ($new_request =~ m/_CONTENTLENGTH_/g) {
      my $len;
      my ($head, $bod) = split('\r?\n\r?\n', $new_request, 2);
      $len = length($bod);
      $new_request =~ s/_CONTENTLENGTH_/$len/g;
    } elsif ($web == 1 && $new_request =~ m/Content-Length:/i) {
      my $len;
      my ($head, $bod) = split('\r?\n\r?\n', $new_request, 2);
      $len = length($bod);
      $new_request =~ s/Content-Length: .*/Content-Length: $len/i;
#      print STDOUT "[FIX] Auto fixed content-length\n"
    }
    if ($new_request =~ m/__CONTENTLENGTH-1__/g) {
      my $len;
      my ($head, $bod) = split('\r?\n\r?\n', $new_request, 2);
      $len = length($bod) - 1;
      $new_request =~ s/__CONTENTLENGTH-1__/$len/g;
    }
    if ($my_info eq "") {
      $my_info = "Baseline";
    }
    print STDOUT "Request No: $request_no (array $i of $#fuzzarray, index $j of $#$bla, $my_info)\n";
    print FOUT "Request No: $request_no (array $i of $#fuzzarray, index $j of $#$bla, $my_info)\n";
    if ($print_stderr == 1) {
      print STDERR "$new_request\n";
      print STDERR "-----------------------------------------------------------------\n";
    }
    $sreq = $new_request;
    $sreq =~ s/\r/\\r/g;    $sreq =~ s/\n/\\n/g;    $sreq =~ s/\t/\\t/g;    $sreq =~ s/~/|/g;
    if ($use_ssl == 1) {
       $csvline = "$ip~$port~HTTPS~$#fuzzarray~$i~$#$bla~$j~";
    } else {
       $csvline = "$ip~$port~HTTP~$#fuzzarray~$i~$#$bla~$j~";
    }
    $csvline .= "$request_no~$file.$request_no-req~$file.$request_no-resp~$fuzzstring~$my_info~$sreq~";
    if ($print_file == 1) {
      open(FREQ, " > $file$sep$request_no$ext");
      print FREQ $new_request;
      close(FREQ);
    }
   if ($filefuzz == 0) {
    $retry_time = 0;
retry_loop:
    $starttime = [gettimeofday]		if ($do_time);
    &send_data($ip, $port, $new_request);
    if ($do_time) {
      $endtime = [gettimeofday];
      $runtime = tv_interval($starttime, $endtime);
      print STDOUT "[INFO] Timing: $runtime\n";
      print FOUT "[INFO] Timing: $runtime\n";
    }
    if (length($response) == 0) {
      $retry_time++;
      goto retry_loop	if ($retry_time == 1);
      print STDOUT "[INFO] Detected possible overflow, Denial-of-Service or bug - 0 byte response in $file.$request_no-resp\n";
      print FOUT "[INFO] Detected possible overflow, Denial-of-Service or bug - 0 byte response in $file.$request_no-resp\n";
      $csvline .= "[INFO] Detected possible overflow, Denial-of-Service or bug - 0 byte response in $file.$request_no-resp;";
    }
    if ($response ne "" && $therex ne "" && $response =~ m/$therex/si) {
      print STDOUT "[INFO] Detected defined result data for " . $theinfo . " in $file.$request_no-resp\n";
      print FOUT "[INFO] Detected defined result data for " . $theinfo . " in $file.$request_no-resp\n";
      $csvline .= "[INFO] Detected defined result data for " . $theinfo . " in $file.$request_no-resp;";
    } elsif ($response ne '' && $response =~ m/>XSS</s) {
      print STDOUT "[INFO] Detected delayed XSS in $file.$request_no-resp\n";
      print FOUT "[INFO] Detected delayed XSS in $file.$request_no-resp\n";
      $csvline .= "[INFO] Detected delayed XSS in $file.$request_no-resp;";
    }
    if ($response =~ m/odbc/i) {
      print STDOUT "[INFO] Detected odbc string response in $file.$request_no-resp\n";
      print FOUT "[INFO] Detected odbc string response in $file.$request_no-resp\n";
      $csvline .= "[INFO] Detected odbc string response in $file.$request_no-resp;";
    }
    if ($response =~ m/jdbc/i) {
      print STDOUT "[INFO] Detected jdbc string response in $file.$request_no-resp\n";
      print FOUT "[INFO] Detected jdbc string response in $file.$request_no-resp\n";
      $csvline .= "[INFO] Detected jdbc string response in $file.$request_no-resp;";
    }
#    if ($response =~ m/<script>alert/i) {
#      print STDOUT "[INFO] Detected possible injected XSS string response\n";
#    }
    if ($response =~ m/^Xss: Xss/s) {
      print STDOUT "[INFO] Detected possible injected XSS header splicing string response\n";
      print FOUT "[INFO] Detected possible injected XSS header splicing string response\n";
      $csvline .= "[INFO] Detected possible injected XSS header splicing string response;";
    }
    if ($response =~ m/[a-z]:\\/ || $response =~ m/\/usr\/.*\// || $response =~ m/\/opt\// || $response =~ m/\/.*\/apache/ || $response =~ m/\/srv\//) {
      print STDOUT "[INFO] Detected possible path disclosure response in $file.$request_no-resp\n";
      print FOUT "[INFO] Detected possible path disclosure response in $file.$request_no-resp\n";
      $csvline .= "[INFO] Detected possible path disclosure response in $file.$request_no-resp;";
    }
    if ($response =~ m/syntax error/ || $response =~ m/error:/i || $response =~ m/query failed/i) { # || $response =~ m// || $response =~ m//) {
      print STDOUT "[INFO] Detected possible sql error response in $file.$request_no-resp\n";
      print FOUT "[INFO] Detected possible sql error response in $file.$request_no-resp\n";
      $csvline .= "[INFO] Detected possible sql error response in $file.$request_no-resp;";
    }
    if ($response =~ m/ORA-[0-9]/ || $response =~ m/error .* sql /i) { # || $response =~ m// || $response =~ m//) {
      print STDOUT "[INFO] Detected possible oracle db error response in $file.$request_no-resp\n";
      print FOUT "[INFO] Detected possible oracle db error response in $file.$request_no-resp\n";
      $csvline .= "[INFO] Detected possible oracle db error response in $file.$request_no-resp;";
    }
    if ($response =~ m/mysql_query/i || $response =~ m/not a valid MySQL/i) {
      print STDOUT "[INFO] Detected possible mysql db error response in $file.$request_no-resp\n";
      print FOUT "[INFO] Detected possible mysql db error response in $file.$request_no-resp\n";
      $csvline .= "[INFO] Detected possible mysql db error response in $file.$request_no-resp;";
    }
    if ($response =~ m/PostgreSQL/ && ($response =~ m/ERROR/ || $response =~ m/query failed/i)) {
      print STDOUT "[INFO] Detected possible mysql db error response in $file.$request_no-resp\n";
      print FOUT "[INFO] Detected possible mysql db error response in $file.$request_no-resp\n";
      $csvline .= "[INFO] Detected possible mysql db error response in $file.$request_no-resp;";
    }
    if ($response =~ m/error .* sql /i || $response =~ m/\]\[DB2\//i || $response =~ m/unexpected .*END-OF-STATEMENT/ || $response =~ m/SQL error/i || $response =~ m/WHERE .*SELECT/ || $response =~ m/error .*while .*processing .*request/i) {
      print STDOUT "[INFO] detected possible sql error response in $file.$request_no-resp\n";
      print FOUT "[INFO] detected possible sql error response in $file.$request_no-resp\n";
      $csvline .= "[INFO] detected possible sql error response in $file.$request_no-resp;";
    }
    if ($response =~ m/\[bootloader\]/is || $response =~ m/^root:.*:0:/s || $response =~ m/:\/bin\/sh/s || $response =~ m/:\/bin\/bash/s) {
      print STDOUT "[INFO] Traversal seemed to work\n";
      print FOUT "[INFO] Traversal seemed to work\n";
      $csvline .= "[INFO] Traversal seemed to work;";
    }
#    if ($response =~ m/FUZZDIR/i) {
#      print STDOUT "[INFO] Detected possible command execution\n";
#    }
#    if ($response =~ m/FUZZEXEC/i) {
#      print STDOUT "[INFO] Detected possible command execution\n";
#    }
    if ($postprocess ne "") {
        $newd = "";
        {
	  local $/= undef;
          open(EX, "$postprocess $file.$request_no-resp | ");
          $newd = <EX>;
          close(EX);
        }
        if ($print_stderr == 1) {
          print STDERR "-----------------------------------------------------------------\n";
          print STDERR "$newd\n";
        }
        if ($print_file == 1) {
          open(FRESP, " > $file.$request_no-resp-pp");
          print FRESP $newd;
          close FRESP;
        }
     if (length($response) == 0) {
      print STDOUT "[INFO] [PP] Detected possible overflow, Denial-of-Service or bug - 0 byte response in $file.$request_no-resp-pp\n";
      print FOUT "[INFO] [PP] Detected possible overflow, Denial-of-Service or bug - 0 byte response in $file.$request_no-resp-pp\n";
     }
     if ($response ne "" && $res ne "" && $response =~ m/$rex/si) {
      print STDOUT "[INFO] [PP] Detected defined result data for " . $info . " in $file.$request_no-resp-pp\n";
      print FOUT "[INFO] [PP] Detected defined result data for " . $info . " in $file.$request_no-resp-pp\n";
     } elsif ($response ne '' && $response =~ m/>XSS</) {
      print STDOUT "[INFO] [PP] Detected delayed XSS in $file.$request_no-resp-pp\n";
      print FOUT "[INFO] [PP] Detected delayed XSS in $file.$request_no-resp-pp\n";
     }
     if ($response =~ m/odbc/i) {
      print STDOUT "[INFO] [PP] Detected odbc string response in $file.$request_no-resp-pp\n";
      print FOUT "[INFO] [PP] Detected odbc string response in $file.$request_no-resp-pp\n";
     }
     if ($response =~ m/jdbc/i) {
      print STDOUT "[INFO] [PP] Detected jdbc string response in $file.$request_no-resp-pp\n";
      print FOUT "[INFO] [PP] Detected jdbc string response in $file.$request_no-resp-pp\n";
     }
     if ($response =~ m/[a-z]:\\/ || $response =~ m/\/usr\/.*\// || $response =~ m/\/opt\// || $response =~ m/\/srv\//) {
      print STDOUT "[INFO] [PP] Detected possible path disclosure response in $file.$request_no-resp-pp\n";
      print FOUT "[INFO] [PP] Detected possible path disclosure response in $file.$request_no-resp-pp\n";
     }
     if ($response =~ m/ORA-[0-9]/ || $response =~ m/error .* sql /i) { # || $response =~ m// || $response =~ m//) {
      print STDOUT "[INFO] [PP] Detected possible oracle db error response in $file.$request_no-resp-pp\n";
      print FOUT "[INFO] [PP] Detected possible oracle db error response in $file.$request_no-resp-pp\n";
     }
     if ($response =~ m/mysql_query/i || $response =~ m/not a valid MySQL/) {
      print STDOUT "[INFO] [PP] Detected possible mysql db error response in $file.$request_no-resp-pp\n";
      print FOUT "[INFO] [PP] Detected possible mysql db error response in $file.$request_no-resp-pp\n";
     }
     if ($response =~ m/PostgreSQL/ && ($response =~ m/ERROR/ || $response =~ m/query failed/i)) {
      print STDOUT "[INFO] [PP] Detected possible mysql db error response in $file.$request_no-resp-pp\n";
      print FOUT "[INFO] [PP] Detected possible mysql db error response in $file.$request_no-resp-pp\n";
     }
     if ($response =~ m/error .* sql /i || $response =~ m/\]\[DB2\//i || $response =~ m/unexpected .*END-OF-STATEMENT/ || $response =~ m/SQL error/i || $response =~ m/WHERE .*SELECT/ || $response =~ m/error .*while .*processing .*request/i) {
      print STDOUT "[INFO] [PP] detected possible sql error response in $file.$request_no-resp-pp\n";
      print FOUT "[INFO] [PP] detected possible sql error response in $file.$request_no-resp-pp\n";
     }
    }
   }
    if ($print_stderr == 1) {
      print STDERR "=================================================================\n";
    }
    print FCSV $csvline . "\n";
    $request_no++;
  }
  $start = 1;
}

close(FOUT);
close(FCSV);

exit 0;

#
# SUBS follow here
#

sub fuzzer {
    my $fuzzing = shift;
    my @replaces = split(/#/, $fuzzing);
    my $places = $#replaces;
    my @ret;
    my $fuzz;
    my $data;
    my $done;
    my $all;
    my $times = 1;
    for (my $i = 0; $i <= $places; $i++) {
      $fuzz = $replaces[$i];
      if ($fuzz =~ m/^TIMES:/i) {
        $times = $fuzz;
        $times =~ s/^TIMES://;
        splice(@replaces, $i, 1); $places--;
        last;
      }
    }
    for (my $i = 0; $i <= $places; $i++) {
      $fuzz = $replaces[$i];
      $all = 0;
      $done = 0;
     for (my $n = 0; $n < $times; $n++) {
      if ($fuzz eq "_ALL_") {
        $all = 1;
        $done = 1;
        push @ret, fz("", "", "Empty");
      }
      if ($fuzz eq "_SQL_" || $all == 1) {
        push @ret, fz("'\"*;--", "", "SQL Injection Force errors with illegal characters");
        push @ret, fz("' OR '1'='1", "", "SQL Injection true");
        push @ret, fz("' AND '1'='2", "", "SQL Injection false");
        push @ret, fz("\" OR \"1\"=\"1", "", "SQL Injection true");
        push @ret, fz("\" OR \"1\"=\"2", "", "SQL Injection false");
        push @ret, fz("') OR '(1'='1", "", "SQL Injection true");
        push @ret, fz("') AND ('1'='2", "", "SQL Injection false");
        push @ret, fz("\") OR (\"1\"=\"1", "", "SQL Injection true");
        push @ret, fz("\") AND (\"1\"=\"2", "", "SQL Injection false");
        push @ret, fz("%%", "", "SQL Injection %% wildecard");
        push @ret, fz("*", "", "SQL Injection * wildecard") if ($smallfuzz == 0);
        $done = 1;
      }
      if ($fuzz eq "_XSS_" || $all == 1) {
        push @ret, fz("'\"><script>alert(\"XSS\")</script><\"'", "><script>alert", "XSS script alert") if ($smallfuzz == 0);
        push @ret, fz("'\"><h1>XSS<\"'", ">XSS<", "XSS style");
        push @ret, fz("XSS%0a%0dXss:%20Xss%0d%0a%0d%0a<html><body><h1>XSS", "\nXss: Xss", "XSS HTTP Header Splicing");
        $done = 1;
      }
      if ($fuzz eq "_FORMATSTRING_" || $all == 1) {
        push @ret, fz("%n%n%n%n", "", "Format String 4x%n") if ($smallfuzz == 0);
        push @ret, fz("%25n25n%25n%25n%25n%25n", "", "Format String 6x%25n") if ($smallfuzz == 0);
        push @ret, fz("%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n", "", "Format String 28x%n");
        push @ret, fz("%25n%25n25n%25n%25n%25n%25n%25n25n%25n%25n%25n%25n%25n25n%25n%25n%25n%25n%25n25n%25n%25n%25n%25n", "", "Format String 24x%25n") if ($smallfuzz == 0);
        $done = 1;
      }
      if ($fuzz eq "_TRAVERSAL_" || $all == 1) {
        push @ret, fz("http://www.mh-sec.de/?mfuzzer=", "heuse", "HTTP include");
        if ($is_unix == 1) {
          push @ret, fz("/../../../../../../../../../etc/passwd", ":/bin/", "Traversal unix /../...");
          push @ret, fz("./../../../../../../../../../etc/passwd", ":/bin/", "Traversal unix ./../...") if ($smallfuzz == 0);
          push @ret, fz("/../../../../../../../../../etc/passwd%00", ":/bin/", "Traversal unix /../...%00");
          push @ret, fz("./../../../../../../../../../etc/passwd%00", ":/bin/", "Traversal unix ./../...%00") if ($smallfuzz == 0);
        }
        if ($is_win == 1) {
          push @ret, fz("/../../../../../../../../../boot.ini", "bootloader", "Traversal windows /../...");
          push @ret, fz("./../../../../../../../../../boot.ini", "bootloader", "Traversal windows ./../...") if ($smallfuzz == 0);
          push @ret, fz("/../../../../../../../../../boot.ini%00", "bootloader", "Traversal windows /../...%00");
          push @ret, fz("./../../../../../../../../../boot.ini%00", "bootloader", "Traversal windows ./../...%00") if ($smallfuzz == 0);
          push @ret, fz("C:\\boot.ini", "bootloader", "Traversal windows C:\\");
          push @ret, fz("C:\\\\boot.ini", "bootloader", "Traversal windows C:\\\\") if ($smallfuzz == 0);
          push @ret, fz("C:\\boot.ini%00", "bootloader", "Traversal windows C:\\%00");
          push @ret, fz("C:\\\\boot.ini%00", "bootloader", "Traversal windows C:\\\\%00") if ($smallfuzz == 0);
        }
        $done = 1;
      }
      if ($fuzz eq "_EXEC_" || $all == 1) {
        push @ret, fz(";id;FUZZEXEC;expr 11111111 + 444;dir;sleep 60;", "11111555", "Exec commands via semicolon ;..;");
        push @ret, fz("id;FUZZEXEC;echo FUZZEXEC;dir;expr 11111111 + 444;sleep 60;", "11111555", "Exec commands via semicolon ..;") if ($smallfuzz == 0);
        push @ret, fz("|echo FUZZEXEC;expr 11111111 + 444", "11111555", "Exec echo commands via pipe");
        push @ret, fz("|sleep 66", "", "Exec echo commands via pipe");
#        push @ret, fz("<!--#echo var=\"FUZZEXEC\" -->", "FUZZEXEC", "Exec echo command via SSI");
#        push @ret, fz("'\"><!--#echo var=\"FUZZEXEC\" --><hr \"'", "FUZZEXEC", "Exec echo command via SSI");
        if ($is_unix == 1) {
          push @ret, fz("<?php passthru ('ls -al / FUZZDIR ; sleep 60');?>", " root .*FUZZDIR", "Exec unix command via php");
          push @ret, fz("'\"><?php passthru ('ls -al / FUZZDIR ; sleep 60');?><hr \"'", " root .*FUZZDIR", "Exec unix command via php");
        }
        if ($is_win == 1) {
          push @ret, fz("<?php passthru ('dir C:\\ FUZZDIR & sleep 60');?>", "Program Files.*FUZZDIR", "Exec windows command via php");
          push @ret, fz("'\"><?php passthru ('dir C:\\ FUZZDIR & sleep 60');?><hr \"'", "Program Files.*FUZZDIR", "Exec windows command via php");
        }
        $done = 1;
      }
      if ($fuzz eq "_BOF_" || $all == 1) {
        push @ret, fz("A"x24, "", "Buffer Overflow 24 characters") if ($smallfuzz == 0);
        push @ret, fz("A"x264, "", "Buffer Overflow 264 characters");
        push @ret, fz("A"x1100, "", "Buffer Overflow 1100 characters") if ($smallfuzz == 0);
        push @ret, fz("A"x11000, "", "Buffer Overflow 11000 characters") if ($smallfuzz == 0);
        push @ret, fz("A"x60000, "", "Buffer Overflow 60000 characters") if ($smallfuzz == 0);
        $done = 1;
      }
      if ($fuzz eq "_NUM_" || $all == 1) {
        push @ret, fz("-1", "", "Number Overflow -1");
        push @ret, fz("0", "", "Number Overflow 0");
        push @ret, fz("1", "", "Number Overflow 1");
        push @ret, fz("127", "", "Number Overflow 127") if ($smallfuzz == 0);
        push @ret, fz("255", "", "Number Overflow 255") if ($smallfuzz == 0);
        push @ret, fz("256", "", "Number Overflow 256") if ($smallfuzz == 0);
        push @ret, fz("32767", "", "Number Overflow 32767") if ($smallfuzz == 0);
        push @ret, fz("65535", "", "Number Overflow 65535") if ($smallfuzz == 0);
        push @ret, fz("65536", "", "Number Overflow 65536") if ($smallfuzz == 0);
        push @ret, fz("2147483647", "", "Number Overflow 2147483647") if ($smallfuzz == 0);
        push @ret, fz("4294967295", "", "Number Overflow 4294967295") if ($smallfuzz == 0);
        push @ret, fz("4294967296", "", "Number Overflow 4294967296");
        $done = 1;
      }
      # THE FOLLOWING STATEMENTS ARE NOT USED BY _ALL_ !
      if ($fuzz eq "_BINARY_") {
        for (my $i = 0; $i < 256; $i++) {
          push @ret, fz(chr($i), "Binary $i", "");
        }
        $done = 1;
      }
      if ($fuzz =~ m/^NUM:/i) {
        my $count = $fuzz;
        $count =~ s/^NUM://;
        for (my $i = 0; $i < $count; $i++) {
          $data = "9$data";
        }
        push @ret, fz($data, "", "Defined number overflow of length " . $count);
        $done = 1;
      }
      if ($fuzz =~ m/^COUNT:/i) {
        my $count = $fuzz;
        my $from;
        my $to;
        $count =~ s/^COUNT://;
        ($from, $to) = split(/-/, $count);
        for (my $i = $from; $i <= $to; $i++) {
          push @ret, fz($i, "", "Count from " . $from . " to " . $to . ", now: " . $i);
        }
        $done = 1;
      }
      if ($fuzz =~ m/^FILE:/i) {
        my $file = $fuzz;
        $file =~ s/^FILE://;
        open (MYF, "< $file");
        while ($data = <MYF>) {
          chomp($data);
          push @ret, fz($data, "", "Line from file " . $file);
        }
        $done = 1;
      }
      if ($fuzz =~ m/^BOF:/i) {
        my $count = $fuzz;
        $count =~ s/^BOF://;
        for (my $i = 0; $i < $count; $i++) {
          $data = "A$data";
        }
        push @ret, fz($data, "", "Defined buffer overflow of length " . $count);
        $done = 1;
      }
      if ($fuzz =~ m/^EXEC:/i) {
        my $execute = $fuzz;
        $execute =~ s/^EXEC://i;
        {
	  local $/= undef;
          open(EX, "$execute | ");
          $data = <EX>;
          close(EX);
        }
        push @ret, fz($data, "", "Data from executable");
        $done = 1;
      }
      if ($fuzz =~ m/^PERL:/i) {
        my $execute = $fuzz;
        $execute =~ s/^PERL://i;
        $data = eval($execute);
        push @ret, fz($data, "", "");
        $done = 1;
      }
      if ($fuzz =~ m/^BIN:/i) {
        my $execute = $fuzz;
        $execute =~ s/^BIN://i;
        $data = chr($execute);
        push @ret, fz($data, "", "");
        $done = 1;
      }
      if ($done == 0) {
        # "REXEC:", "RPERL:" and "COPY:" also get here
        push @ret, fz($fuzz, "", "Predefined data: $fuzz");
      }
     }
    }
    return (@ret);
}

sub fz {
    my $fuzz;
    my $rexi;
    my $info;
    
    ($fuzz, $rexi, $info) = @_;
    
    if ($request_type eq "xml") {
      if ($fuzz =~ m/[<>]/) {
        $data = $info . "#;Y" . $rexi . "#;Y" . "<![CDATA[" . $fuzz . "]]>";
      } elsif ($fuzz =~ m/"/) {
        $fuzzz = $fuzz;
        $fuzzz =~ s/"/%22/gs;
        $data = $info . "#;Y" . $rexi . "#;Y" . $fuzzz;
      }
    } elsif ($request_type eq "json" && $fuzz =~ m/\"/) {
      $fuzzz = $fuzz;
      $fuzzz =~ s/\"/\\\"/g;
      $data = $info . "#;Y" . $rexi . "#;Y" . $fuzzz;
    } else {
      $data = $info . "#;Y" . $rexi . "#;Y" . $fuzz;
    }

    return ($data);
}

sub send_data {
    my $remote;
    my $rline;
    my $dest;
    my $port;
    my $times;
    my $done = 0;

    ($dest, $port, $rline) = @_;

    if ($print_file == 1) {
      open(FRESP, " > $file.$request_no-resp");
    }
    
    if ($use_udp == 1) {
      $remote = IO::Socket::IP->new(Proto=>"udp", PeerAddr=>$dest, PeerPort=>"$port");
      unless ($remote) {
        print STDOUT "Error: cannot connect to udp daemon on $dest:$port, retrying in 5 seconds\n";
        sleep(5);
        $remote = IO::Socket::IP->new(Proto=>"udp", PeerAddr=>$dest, PeerPort=>"$port");
        unless ($remote) {
          print STDOUT "Error: cannot connect to udp daemon on $dest:$port, retrying in 15 seconds\n";
          sleep(15);
          $remote = IO::Socket::IP->new(Proto=>"udp", PeerAddr=>$dest, PeerPort=>"$port");
          unless ($remote) {
            print FOUT "Error: cannot connect to udp daemon on $dest:$port\n";
            die "Error: cannot connect to udp service on $dest:$port, aborting"; 
          }
        }
      }
      $remote->autoflush(1);
    } elsif ($use_ssl == 1) {
        if (length($cert) > 0) {
          $remote = IO::Socket::SSL->new(Proto=>"tcp", PeerAddr=>$dest, PeerPort=>"$port", Reuse=>1, SSL_verify_mode=>0, SSL_use_cert=>1, SSL_cert_file=>$cert, SSL_ca_file=>$cert, SSL_key_file=>$cert);
        } else {
          $remote = IO::Socket::SSL->new(Proto=>"tcp", PeerAddr=>$dest, PeerPort=>"$port", Reuse=>1, SSL_verify_mode=>0);
        }
        unless ($remote) {
          print STDOUT "Error: cannot connect to SSL daemon on $dest:$port, retrying in 5 seconds\n";
          sleep(5);
          if (length($cert) > 0) {
            $remote = IO::Socket::SSL->new(Proto=>"tcp", PeerAddr=>$dest, PeerPort=>"$port", Reuse=>1, SSL_verify_mode=>0, SSL_use_cert=>1, SSL_cert_file=>$cert, SSL_ca_file=>$cert, SSL_key_file=>$cert);
          } else {
            $remote = IO::Socket::SSL->new(Proto=>"tcp", PeerAddr=>$dest, PeerPort=>"$port", Reuse=>1, SSL_verify_mode=>0);
          }
          unless ($remote) {
            print STDOUT "Error: cannot connect to SSL daemon on $dest:$port, retrying in 15 seconds\n";
            sleep(15);
            if (length($cert) > 0) {
              $remote = IO::Socket::SSL->new(Proto=>"tcp", PeerAddr=>$dest, PeerPort=>"$port", Reuse=>1, SSL_verify_mode=>0, SSL_use_cert=>1, SSL_cert_file=>$cert, SSL_ca_file=>$cert, SSL_key_file=>$cert);
            } else {
              $remote = IO::Socket::SSL->new(Proto=>"tcp", PeerAddr=>$dest, PeerPort=>"$port", Reuse=>1, SSL_verify_mode=>0);
            }
            unless ($remote) {
              print FOUT "Error: cannot connect to SSL daemon on $dest:$port\n";
              die "Error: cannot connect to SSL daemon on $dest:$port, aborting"; 
            }
          }
        }
    } else {
        $remote = IO::Socket::IP->new(Proto=>"tcp", PeerAddr=>$dest, PeerPort=>"$port", Timeout=>$connect_timeout);
        unless ($remote) {
          print STDOUT "Error: cannot connect to daemon on $dest:$port, retrying in 5 seconds\n";
          sleep(5);
          $remote = IO::Socket::IP->new(Proto=>"tcp", PeerAddr=>$dest, PeerPort=>"$port", Timeout=>$connect_timeout);
          unless ($remote) {
            print STDOUT "Error: cannot connect to daemon on $dest:$port, retrying in 15 seconds\n";
            sleep(15);
            $remote = IO::Socket::IP->new(Proto=>"tcp", PeerAddr=>$dest, PeerPort=>"$port", Timeout=>$connect_timeout);
            unless ($remote) {
              print FOUT "Error: cannot connect to daemon on $dest:$port\n";
              die "Error: cannot connect to daemon on $dest:$port, aborting"; 
            }
          }
        }
        $remote->autoflush(1);
    }
    my $sel = new IO::Select($remote);
    print $remote $rline;
    $response = "";
    $rline = "";
    $times = time;
    while ($done == 0) {
      my @setset = IO::Select->select($sel, undef, $sel, 0.1);
      if ($#setset > 0) {
        # this needs read() if non-lines based protocols are fuzzed
        $rline=<$remote>;
        if ($rline) {
          if ($print_stderr == 1) {
            print STDERR "$rline";
          }
          if ($print_file == 1) {
            print FRESP $rline;
          }
          $response = $response . $rline;
        } else {
          $done = 1;
        }
      }
      if (($times + $response_timeout <= time) || ($use_udp == 1 && $rline ne "")) {
        $done = 1;
      }
    }
    close $remote;

#print "HERE! $learn_cookies - ...\n";
    $learned = 0;
    if ($learn_cookies == 1 && $response =~ m/\nSet-Cookie:/is) {
      my $learned = 0;
      my $found = 0;
      $learned = 1;
      $tmpres = $response;
      $tmpres =~ s/.*?set-cookie:/Set-Cookie:/is;
#print "SETCOOKIE: $tmpres\n";
      while ($tmpres =~ m/^Set-Cookie:/is) {
        $tmpres2 = $tmpres;
        $tmpres2 =~ s/.*?\n//;
        $tmpres2 =~ s/.*?set-cookie:/Set-Cookie:/is;
        $tmpres =~ s/\n.*//s;
        $tmpres =~ s/[\r ]//g;
        $tmpres =~ s/Set-Cookie://;
#print "LEARNING: $tmpres\n";
        $tmpres =~ s/;.*//;
        my $cname = $tmpres;
        $cname =~ s/=.*/=/;
        $found = 0;
        for (my $j = 0; $j <= $#cookiejar; $j++) {
          if ($cookiejar[$j] =~ m/^$cname/) {
            $found = 1;
            $cookiejar[$j] = $tmpres;
#print "UPDATE: ($cname) $tmpres\n";
          }
        }
        if ($found == 0) {
          push @cookiejar, $tmpres;
#print "NEW: $tmpres\n";
        }
        $tmpres2 = $tmpres;
      }
      if ($learned == 1 && $use_cookiejar == 1) {
        # update jarfile $cookiejar
        my $atom = "";
        for (my $j = 0; $j <= $#cookiejar; $j++) {
          $atom = $atom . $cookiejar[$j] . "\n";
        }
        open(FJAR, " > $cookiejar_file");
        print FJAR "$atom";
        close FJAR;
      }
    }
    
   if ($trigger != 2) {
    print STDERR "$response"	if ($print_stderr == 1);
    if ($print_file == 1) {
      open(FRESPCLEAN, " > $file.$request_no-clean_resp");
      my ($head, $body) = split('\r?\n\r?\n', $response, 2);
      my ($first, $rest) = split('\n', $head, 2);
      if ($request_no > 0) {
        $body =~ s/\Q$fuzzstring\E//g;
        if ($fuzzstring =~ m/^AAAAAAAA/) {
          $body =~ s/AAAAAAAA*\.*//g;
        }
        $newfuzzstring = $fuzzstring;
        $newfuzzstring =~ s/>/&gt;/g;
        $newfuzzstring =~ s/</&lt;/g;
        $body =~ s/\Q$newfuzzstring\E//g;
      }
      print FRESPCLEAN "$first\n$body"	if (length($response) > 0);
      print FRESP "$response";
      close(FRESPCLEAN);
      close(FRESP);
    }
    $sreq = $response;
    $sreq =~ s/\r/\\r/g;    $sreq =~ s/\n/\\n/g;    $sreq =~ s/\t/\\t/g;    $sreq =~ s/~/|/g;
    $csvline .= "$sreq~";
    if ($print_stderr == 1) {
      print STDERR "\n";
    }
   }

    if ($trigger == 1 && $response =~ m/\Q$trigger_text\E/s) {
      $trigger = 2;
      &send_data($ip, $port, $trigger_data);
      $trigger = 1;
    }
}

sub readfile{
  my $file = shift;
  my $target;
  my @target;
  my $port = "";
  my $ip = "";
  my $request;
  
  (undef, $target) = split ('-', $file);
  my @targets = split ('\.', $target);
  s/^0+(?=\d)// foreach @targets ;
  $ip = "$targets[0].$targets[1].$targets[2].$targets[3]";
  $port= $targets[4];
  $ip = ""		if ($ip =~ m/\.\./ || $ip =~ m/^\./ || $ip =~ m/\.$/);
#print "1 $ip $port\n";
  if ($ip eq "" && $targets[0] =~ m/\..*\./ && $targets[2] =~ m/^[1-9][0-9]*$/) {
    $ip = $targets[0];
    $port = $targets[1];
#print "2 $ip $port\n";
  }
  {
        local $/= undef;
	open(FH,"< $file") or die "Error: cannot open file $file\n";
        $request = <FH>;
	close(FH);
  }
  if ($web == 1 && $ip eq "" && $my_ip eq "" && $request =~ m/\nHost: /si) {
    my $foo = $request;
    $foo =~ s/.*\nHost: *//si;
    $foo =~ s/\r?\n.*//s;
    $ip = $foo;
    $ip =~ s/:.*//;
    if ($foo =~ m/:/) {
      $port = $foo;
      $port =~ s/.*://;
    } else {
      if ($use_ssl == 1) {
        $port = 443;
      } else {
        $port = 80;
      }
    }
#print "3 $ip $port\n";
  }
  $port = ""	if ($ip eq "");
  return ($ip, $port, $request);
}

# return all cookies from request in A=B;C=D;E=F notation
sub readcookies{
  my $cooks = shift;
  my $oldbody = $cooks;
  my $newreq = "";

#print "\nORIG:\n$cooks\n";
  $cooks =~ s/\r?\n\r?\n.*//s;
  $oldbody =~ s/.*?\r?\n\r?\n//s;
  my @hdrtmp = split (/\n/, $cooks);
  $cooks = "";
  for (my $i = 0; $i <= $#hdrtmp; $i++) {
#print "H $i $hdrtmp[$i]\n";
    if ($hdrtmp[$i] =~ m/^cookie:/i) {
      $hdrtmp[$i] =~ s/^cookie://i;
      $hdrtmp[$i] =~ s/[\r ]//g;
      $hdrtmp[$i] = $hdrtmp[$i] . ";" 	if ($hdrtmp[$i] !~ m/;$/);
      $cooks = $cooks . $hdrtmp[$i];
    } else {
      $newreq = $newreq . "$hdrtmp[$i]\r\n";
      $hdrtmp[$i] = ""	
    }
  }
  $newreq = $newreq . "{__COOKIES__}" . "\r\n" . $oldbody;
  $cooks =~ s/;;/;/g;
  $cooks =~ s/;$//;
#print "\nNEW:\n$cooks\n$newreq\n";
  return ($newreq, $cooks);
}
