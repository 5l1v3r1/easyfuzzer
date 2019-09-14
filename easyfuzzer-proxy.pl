#!/usr/bin/perl

$directory = "/tmp/easyfuzzer";
#$file = "request.txt";
$exec = "easyfuzzer.pl";
$conv = "prepare4easyfuzzer.pl -f";
# the following extensions are ignored in requests
@extensions = ( 'js', 'css', 'txt', 'pdf', 'doc', 'jpg', 'gif', 'png', 
                'bmp', 'ico', 'swf', 'xml');
$ssl = "";
$all=0;

$infile = shift;

if ($infile eq "-a") {
  $all=1;
  $infile = shift;
}

if ($infile eq "") {
  print STDOUT "Syntax: [-a] easyfuzzer-proxy.pl FILE";
  print STDOUT "Do not run this directly, if you really want: FILE is a request\n";
  exit(1);
}

open (IN, "< $infile");

$read = <IN>;

if ($read eq "") {
  print STDERR "Can not open file $infile\n";
  exit(-1);
}

if ($read !~ m| http.*//.*/|) {
  print STDERR "Not a valid proxy request, aborting ...\n";
  exit(-1);
}

if ($read !~ m/^POST / && ( $read !~ m/^GET / || $read !~ m/\?/ )) {
  print STDERR "Not a POST request or a GET request with options, ignoring ...\n";
  exit(0);
}

if ($read =~ m/^POST / && ( $read =~ m/&__VIEWSTATE=/ || $read =~ m/^__VIEWSTATE=/ )) {
  print STDERR "Contains .NET __VIEWSTATE variable, aborting ...\n";
  exit(-1);
}

#if ($read =~ m/^POST / && $read =~ m/^Content-Type: multipart/ ) {
#  print STDERR "POST request is multipart type, this is not supported yet!! aborting ...\n";
#  exit(-1);
#}

if ($read =~ m| https://|) {
  $ssl = "-s";
}

$read =~ s|.* https?://||;
$connect = $read;
$connect =~ s,/.*,,;
($host, $port) = split(":", $connect);
if ($port eq "") {
  if ($ssl eq "") {
    $port = 80;
  } else {
    $port = 443;
  }
}

$read =~ s/\?.*//;
$read =~ s/;.*//;
$read =~ s,/,_,g;
$read =~ s/[^A-Za-z0-9_.-]//g;
$read =~ tr/A-Z/a-z/;

$ext = $read;
$ext =~ s/.*\.//;
$ext =~ s,/.*,,;
if ($ext ne "") {
  foreach (@extensions) {
    if ($ext eq $_) {
      print STDERR "Extension $ext is on blacklist, ignoring request ...\n";
      exit(0);
    }
  }
}

if (length($read) > 100) {
  $read = substr($read, 0, 110);
}

$read =~ s/http_1.1//;
$read = substr($read, 0, 100);
$targetdir = $directory . "/" . $read;
$targetfile = $targetdir . "/" . $read . ".txt";

system("mkdir -p $directory");
system("chmod 1777 $directory");
open (CHECK, "< $targetfile");
$reading = <CHECK>;

if ($reading ne "") {
  if ($all == 0) {
    print STDERR "Request was already seen\n";
    exit(0);
  } else {
    $count=0;
    while ($reading ne "") {
      $targetdir = $directory . "/" . $read . "_" . $count;
      $targetfile = $targetdir . "/" . $read . "_" . $count . ".txt";
      open (CHECK, "< $targetfile");
      $reading = <CHECK>;
      $count++;
    }
    print STDERR "Re-executing request (count: $count)\n";
  }
}

system("mkdir $targetdir");

print STDOUT "Executing: $conv $infile $targetfile\n";
system("$conv $infile $targetfile");

$system = "$exec $ssl -O -X $targetfile $host $port";
print STDOUT "Executing: $system\n";
system($system);

print STDOUT "Executing easyfuzzer-diff.sh $targetfile\n";
system("easyfuzzer-diff.sh $targetfile");

print STDOUT "Saving found potential vulnerabilties to $directory/easyfuzzer.out\n";
system("grep -w INFO $targetfile.out | tee -a $directory/easyfuzzer.out");

print STDOUT "Done with easyfuzzer-proxy.pl\n";
