#!/usr/bin/perl
#
#
#
$infile = shift;
$outfile = shift;

if ($infile eq "" || $infile eq "-h" || $infile eq "--help" || $outfile eq "") {
  print STDOUT "wbxml2request.pl WBXML-FILE OUTPUT-FUZZ-FILE\n";
  print STDOUT "Converts a wbxml file to easyfuzzer/sqlfuzzer/pita2_fuzzer format files\n";
  exit;
}

{
  local $/= undef;
  open IN, "< $infile"	|| die "error opening $infile";
  $contents = <IN>;
  close(IN);
}
die "input file is empty\n"	if (length($contents) < 20);

($head, $body) = split('\r?\n\r?\n', $contents, 2);

print "Working on $infile\n";
if ($head !~ /^POST/) {
  print "File seems to have only wbxml content, no HTTP header, note that you will have to add an HTTP header yourself.\n";
  $head = "";
  $body = $contents;
}

$body =~ s/\03[A-Za-z0-9_=?\/.:-].*?\00/\03__FUZZ__{$&#_ALL_}\00/gs;
$body =~ s/_{\03/_{/g;
$body =~ s/\00#_/#_/g;

open OUTF, " > $outfile" || die "Can not create outputfile $outfile\n";

if ($head ne "") {
  $head =~ s/Content-Length: .*/Content-Length: __CONTENTLENGTH__/g;
  $head =~ s/HTTP\/1\../HTTP\/1.0/;
  if ($head =~ m/^POST http/) {
    $head =~ s/^POST https?:\/\//POST /;
    $head =~ s/^POST [A-Za-z0-9_.:-]*\//POST \//;
  }
  print OUTF $head . "\r\n\r\n";
}

print OUTF $body;
close OUTF;

print "Done!\n";
