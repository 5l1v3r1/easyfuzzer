#!/usr/bin/perl
#
#
#
no warnings 'deprecated';

$infile = shift;
$outfile = shift;
$contents = "";
$counter = 0;
$debug = 0;

if ($infile eq "" || $infile eq "-h" || $infile eq "--help") {
  print STDOUT "wsdl2request.pl WDSL-FILE OUTPUT-FILE-TEMPLATE\n";
  print STDOUT "Converts a soap wsdl file to easyfuzzer/sqlfuzzer/pita2_fuzzer format files\n";
  exit;
}

{
  local $/= undef;
  open IN, "< $infile"	|| die "error opening $infile";
  $contents = <IN>;
  close(IN);
}
die "input file is empty\n"	if (length($contents) < 20);

$url = $contents;
$url =~ s/.*<soap:address//is;
$url =~ s/>.*//s;
$url =~ s/.*location=//is;
$url =~ s/\"//g;
$url =~ s/[ \t].*//s;
$namespace = $contents;
$namespace =~ s/.*?targetnamespace=//is;
$namespace =~ s/>.*//s;
$namespace =~ s/\"//g;
$namespace =~ s/[ \t].*//s;
$post_url = $url;
$host = $url;
if ($host =~ m/https:/) {
  $ssl = 1;
  $host =~ s,https://,,;
  $host =~ s,/.*,,;
} else {
  $ssl = 0;
  $host =~ s,http://,,;
  $host =~ s,/.*,,;
}
$post_url =~ s,.*://,,;
$post_url =~ s,^[^/]*,,;

die ("not a soap file\n")	if ($post_url eq "" || $namespace eq "" || $contents !~ m/<.*types>/is);

print "Namespace: $namespace\n";

$xml = "<?xml version=\"1.0\" ?>\r\n";

$contents =~ s/.*<[a-zA-Z]*:?types>//is;
$contents =~ s/<\/[a-zA-Z0-9_-]*:?types>.*//is;

@parts = split (/<\/?[a-zA-Z]*:?schema/, $contents);
push @parts, $contents		if ($#parts == -1);

for ($p = 0; $p <= $#parts; $p++) {
  next		if ($p % 2 == 0 && $p < $#parts); # really? dunno

  $tmpnamespace = $parts[$p];
  $tmpnamespace =~ s/>.*//s;
  if ($tmpnamespace =~ m/targetnamespace=/si) {
    $tmpnamespace =~ s/.*targetnamespace=//si;
    $tmpnamespace =~ s/\"//g;
    $tmpnamespace =~ s/[ \t].*//s;
    print "New namespace: $tmpnamespace\n"	if ($tmpnamespace ne $namespace);
    # more? other post_url or host?
  } else {
    $tmpnamespace = $namespace;
  }
  $work = $parts[$p];

trynext:
  goto nonext			if ($work !~ m/<[A-Za-z0-9]*:?element name=/is);
  $work =~ s/.*?<[A-Za-z0-9]*:?element name=//is;
  $function = $work;
  $function =~ s/>.*//s;
  $function =~ s/.*name=//is;
  $function =~ s/\"//g;
  $function =~ s/[ \t].*//s;
  
  die ("can not find end segment for element name $function\n")		if ($work !~ m/<\/[A-Za-z0-9]*:?element>/s);
  $tmpwork = $work;
  $tmpwork =~ s/.*?>//s;
  $tmpwork =~ s/<\/[A-Za-z0-9]*:?element>.*//s;
  $work =~ s/.*?<\/[A-Za-z0-9]*:?element>//s;
  
  print "Function $function\n";

  $soapaction = $tmpnamespace . "/" . $function;
  $header = "<soapenv:Envelope xmlns:scr=\"$tmpnamespace\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Header/>";
  $body_begin = "<soapenv:Body><scr:$function>";
  $body_end = "</scr:$function></soapenv:Body></soapenv:Envelope>";

  $tmpwork =~ s/[ \t\n][ \t\n]*/ /gs;
  $tmpwork =~ s/\r//gs;
  $body = "";
  @entries = split (/[<>]/, $tmpwork);
  for ($e = 0; $e <= $#entries; $e++) {
    if ($entries[$e] =~ m/ type=/) {
      $name = $entries[$e];
      $name =~ s/.* name=//;
      $name =~ s/\"//g;
      $name =~ s/ .*//;
      $type = $entries[$e];
      $type =~ s/.* type=//;
      $type =~ s/\"//g;
      $type =~ s/ .*//;
      $type =~ s/.*://;
      $value = "_COUNTER_";
      $value = "foo_COUNTER_"	if ($type =~ m/string/i);
      $value = "true"		if ($type =~ m/bool/i);
      $value = "Zm9vYmFyCg=="	if ($type =~ m/base64/i);
      $value = "2008-11-11T11:11:11+01:00"	if ($type =~ m/dateTime/i);
      # what do we do with arrays?
      $body .= "<scr:$name>__FUZZ__{$value#_ALL_}</scr:$name>";
    }
  }
  
  $request = $xml . $header . $body_begin . $body . $body_end;

  if ($debug != 1) {
    open FOUT, "> $outfile-$function.txt";
    print FOUT "POST $post_url HTTP/1.0\r\nHost: $host\r\nUser-Agent: easyfuzzer\r\nContent-type: text/xml; charset=\"UTF-8\"\r\n";
    print FOUT "SOAPAction: \"$soapaction\"\r\n";
    print FOUT "Content-length: __CONTENTLENGTH__\r\n\r\n$request";
    close(FOUT);
  } else {
    print "Function $function\n";
  }

  goto trynext		if ($work =~ m/<[A-Za-z0-9]*:?element name=/is);
  nonext:
}
