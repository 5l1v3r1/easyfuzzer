#!/usr/bin/perl
$go = 0;
$do_fuzz = 0;
$do_cookie = 0;
while ($go == 0) {
  $infile = shift;
  if ($infile eq "-c") {
    $do_cookie = 1;
  } elsif ($infile eq "-f") {
    $do_fuzz = 1;
  } elsif ($infile eq "-h" || $infile eq "") {
    print "Syntax: easyprepare4fuzzer.pl [-c] [-f] infile outfile\n";
    print "-f prepares fuzzing for all get/post data, -c prepares cookie fuzzing\n";
    exit(-1);
  } else {
    $go = 1;
  }
}
$outfile = shift;
$first = 0;
$post = 0;
$multipart = 0;
$json = 0;
open (IN, "< $infile");

if (length($outfile) > 250) {
  $outfile = substr $outfile, 0, 250;
}

$read = <IN>;

if (! $read) {
  print "Syntax: easyprepare4fuzzer.pl IN-FILE OUT-FILE\n";
  print "prepares IN-FILE to be used for easy fuzzing\n";
  print "File is usually a copy'n paste from webscarab\n";
  exit(1);
}

open (OUT, "> $outfile") || die "Can not create output file\n";

if ($read =~ m/^POST /) {
  $post = 1;
}

$read =~ s/HTTP\/.\../HTTP\/1.0/;
$read =~ s/\r//g;
$read =~ s/ https?:\/\/.*?\// \//;

chomp($read);

if ($do_fuzz == 1 && $read =~ m/\?/) {
  ($uri, $da) = split('\?', $read);
  ($data, $end) = split(' ', $da);
  $data .= "&";
  $data =~ s/=.*?&/=__FUZZ__{$&#_ALL_}&/g;
  $data =~ s/&#_ALL_/#_ALL_/g;
  $data =~ s/__FUZZ__{=/__FUZZ__{/g;
  $data =~ s/&$//;
  $data .= "__FUZZ__{#&v=1&verbose=1&d=1&debug=1&admin=1}";
  $read = $uri . "?" . $data . " " . $end;
}

print OUT "$read\r\n";

while ($read = <IN>) {
  if ($first == 1) {
    if ($post == 1) {
      if ($do_fuzz == 1) {
        if ($multipart == 1) {
          if ($read =~ m/^Content-Disposition:/i) {
            print OUT "$read";
            $read = <IN>; # empty
            print OUT "$read";
            $bufx = "";
            $read = "";
            do {
              $bufx = $bufx . $read;
              $read = <IN>;
            } while ($read !~ m/^--------------------------/);
            chomp($bufx);
            $bufx =~ s/\r$//;
            $bufx = "__FUZZ__{" . $bufx . "#_ALL_}\r\n";
            print OUT "$bufx";
            $data = $read;
          } else {
            $data = $read;
          }
        } elsif ($json == 1 || $read =~ m/^{\"/) {
          print "Warning: autodetecting JSON\n"	if ($json == 0);
          $read =~ s/:[^{]"?.*?"?[,}]/~~~$&/g;
#          $read =~ s/\"__FUZZ__{{.*?}/\[{/g;
#          $read =~ s/:[^{]"?.*?"?[,}]/~~~$&/g;
          @vallist = split /~~~/, $read;
          $data = "";
          for (my $i = 0; $i <= $#vallist; $i++) {
            $curval = $vallist[$i];
            if ($curval =~ m/^:[^{]"?.*?"?[,}]/ && $curval !~ m/^:\[{/) {
              $newval = ":__FUZZ__{"; $index = 1;
              if ($curval =~ m/:\"/) {
                $newval = ":\"__FUZZ__{"; $index = 2;
              }
              substr $curval, 0, $index, "";
              $tmp = $curval;
              if ($index == 2) {
                $tmp =~ s/\".*//;
                $newval .= $tmp . "#_ALL_}\"";
                $curval =~ s/.*?\"//;
                $newval .= $curval;
                $curval = $newval;
              } else {
                $comma = index $curval, ',';
                $bracket = index $curval, '}';
                $pos = $comma;
                $pos = $bracket 	if ($bracket < $comma && $bracket >= 0);
                $tmp =~ s/[,}].*//;
                $newval .= $tmp . "#_ALL_}";
                substr $curval, 0, $pos, "";
                $newval .= $curval;
                $curval = $newval;
              }
            }
            $data .= $curval;
          }
        } elsif ($read =~ m/^[A-Za-z0-9_-].*=/) {
          $data = $read . "&";
          $data =~ s/=.*?&/=__FUZZ__{$&#_ALL_}&/g;
          $data =~ s/&#_ALL_/#_ALL_/g;
          $data =~ s/__FUZZ__{=/__FUZZ__{/g;
          $data =~ s/&$//;
          $data .= "__FUZZ__{#&v=1&verbose=1&d=1&debug=1&admin=1}";
        }
      } else {
        $data = $read;
      }
      print OUT "$data";
    }
  } else {
    $read =~ s/\r//g;
    chomp($read);
    $multipart = 1	if ($read =~ /^Content-Type: multipart/i);
    $json = 1		if ($read =~ /^Content-Type: .*json/i);
    if ($read =~ m/^Keep-Alive:/i || $read =~ m/^Accept-Encoding:/i || $read =~ m/^Proxy/i) {
      # delete such lines
    } elsif ($read eq "") {
      $first = 1;
      print OUT "\r\n";
    } else {
      if ($read =~ m/^Connection:/i) {
        $read = "Connection: Close";
      } elsif ($read =~ m/^Content-Length:/i) {
        $read = "Content-Length: __CONTENTLENGTH__";
      } elsif ($do_cookie == 1 && $read =~ m/^Cookie:/i) {
        $data = $read;
        $data =~ s/^cookie: *//i;
        if ($read !~ m/;$/) {
          $data .= ";";
        }
        $data =~ s/=.*?;/=__FUZZ__{$&#_ALL_};/g;
        $data =~ s/__FUZZ__{=/__FUZZ__{/g;
        $data =~ s/;#_ALL_/#_ALL_/g;
        $data =~ s/;$//;
        $read = "Cookie: " . $data;
      }
      print OUT "$read\r\n";
    }
  }
}

close (OUT);
close (IN);

exit(0);
