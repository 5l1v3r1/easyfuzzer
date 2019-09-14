#!/bin/bash
#
# Downloads an WSDL URL, and dumps all its SOAP requests in the fuzz file
# format in individual files. If the -f option is supplied, it
# automatically fuzzes them too afterwards.
#
DIR=`dirname $0`
test "$DIR" = "." && DIR=$(which $0 | sed "s/`basename $0`//")
. $DIR/../config || exit 1

test -z "$2" -o "$1" = -h && { echo "Syntax: $0 [-f] WSDL-URL OUTPUT-FILENAME" ; echo "Downloads the WSDL file, parses the WSDL into fuzzing requests and then (if -f was supplied) fuzzes all entries."; exit 1; }

FUZZ=
SSL=
HTML=
test "$1" = -f && { FUZZ=yes ; shift ; }
echo $1|grep -q https:// && SSL=yes

test "$SSL" = yes && getssl.sh "$1" > "$2" || geturl.sh "$1" > "$2"

grep -qi '<html' "$2" && HTML=yes
test -s "$2" -o "$HTML" = yes || { echo "Invalid WSDL URL $1, please check the output file $2"; exit 1 ; }
OUT=`echo $2|sed 's/\.[a-zA-Z0-9_-]*$//'`

wsdl2request.pl "$2" "$OUT"

test "$FUZZ" = yes && {
  for i in ${OUT}*.txt ; do
    PORT=
    SSLOPT=
    HOST=`grep "^SOAPAction:" "$i" | sed 's|.*://||' | sed 's|[:/].*||'`
    P=`grep "^SOAPAction:" "$i" | sed 's|.*://||' | sed 's|/.*||'`
    echo $P | grep -q : && PORT=`echo $P | sed 's/.*://'`
    egrep -q "SOAPAction.*https" "$i" && SSLOPT=-s
    OF=`echo $i|sed 's/\.txt$/-sql.txt/'`
    cp -f "$i" "$OF";
#    sqlfuzzer.pl $SSLOPT -O -X $OF $HOST $PORT &
    easyfuzzer.pl $SSLOPT -O -X $i $HOST $PORT
    easyfuzzer_analysis.sh "$i"
  done
  echo
  echo
  echo
  echo Done fuzzing.
  echo Please review the following files:
  for i in `ls ${OUT}*.txt|grep -v '\.md5\.txt'` ; do echo -n "$i.html  "; done; echo
  echo
  echo Please review the following output:
  grep -w INFO --no-filename *.txt.out|egrep -v 'Error|Warning'
}
echo
echo Done.
