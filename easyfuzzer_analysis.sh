#!/bin/bash
F="$1"
test -n "$1" && {
  D=`dirname $1`
  test "$D" = "." || {
    cd "$D" || exit 1
    F=`echo $1|sed 's/.*\///'`
  }
}
test -s $F.0-clean_resp || {
  echo Error: $F.0-clean_resp does not exist or is empty
  echo Creates md5sum on all -clean_resp files and saves all filenames to
  echo FILE.md5-CHECKSUM. It then performs diffs against the baseline output.
  echo It generates an html result file, with the name MAINFILE.html
  echo It also generates MAINFILE.diff.txt and MAINFILE.html
  echo
  echo Hints:
  echo   FILE.xxx.md5.txt     contains the filenames which share the same hash
  echo   FILE.xxx.md5.txt.html the request filenames whose results share the same hash
  echo   FILE.xxx.md5.txt-out contains the details of what generated each filename
  echo   FILE.xxx.md5.txt.diff.txt  is the diff to the baseline .0-clean_resp file
  echo   FILE.diff.txt        contains all diff files
  echo   FILE.html            is the html result file
  exit 1
}
echo Generating MD5 for $F
for i in $F.*-clean_resp; do
   MD5=`md5sum "$i"|awk '{print$1}'`
   echo "$i" >> $F.$MD5.md5.txt
done
for i in $F.*.md5.txt; do
  for j in `cat $i`; do
    n=`echo $j|sed "s/$F\.//"|sed 's/-.*//'`
    grep "No: $n " $F.out
  done | sort -k 2 -n | uniq > ${i}-out
  echo "<html><head><title>$i</title></head><body>" > $i.html
  for ltmp in `cat $i`; do
    lfile=`echo $ltmp|sed 's/clean_resp/req/'`
    echo "<a href=\"$lfile\">$lfile</a><br>"
  done >> $i.html
#  awk '{print"<a href=\""$1"\".html>"$1"</a><br>"}' $i >> $i.html
  echo "</body></html>" >> $i.html
done
echo Generating DIFF for $F
> $F.diff.txt
echo "<html><head><title>Diff Fuzz $F</title><STYLE type=text/css>body { font-size: 10px; color: #240024; } table { padding: 0.1em; } td { padding: 0.1em; font-size: 11px; font-color: #240024; } td#wrong { color: #240000;</STYLE></head><body>" > $F.html
echo "<b>Basis Fuzz File:</b> <a href=\"$F\">$F</a><p><hr>" >> $F.html
echo "<b>POTENTIAL FINDINGS</b><p>" >> $F.html
grep -w INFO $F.out | sed 's/ in / in <a href="/' > $F.html.tmp
while read LINE; do
  FILE=`echo $LINE|sed 's/.*="//'|sed "s/.*\///"`
  FIL=`echo $FILE|sed 's/resp/req/'`
  LINE=`echo $LINE|sed 's/ <a .*//'`
  echo "$LINE <a href=\"$FILE\">$FILE</a> from <a href=\"$FIL\">$FIL</a><p>" >> $F.html
done < $F.html.tmp
rm $F.html.tmp

echo "<hr><b>DIFF OUTPUT<p>Global DIFF File:</b> <a href=\"$F.diff.txt\">$F.diff.txt</a><p>" >> $F.html
echo "<TABLE>" >> $F.html
echo "<tr><td>MD5SUM</td><td>FUZZING INPUTS</td><td>ENTRIES</td><td>EXAMPLE REQUEST FILE</td><td>EXAMPLE RESPONSE FILE</td><td>RESPONSE SIZE</td><td>DIFF FILE</td><td>DIFF SIZE</td></tr>" >> $F.html
MAIN=`grep -l $F.0-clean_resp $F.*.md5.txt`
echo "<tr><td><a href=\"$MAIN.html\">$MAIN</a></td><td><a href=\"${MAIN}-out\">${MAIN}-out</a></td><td>`wc -l $MAIN|awk '{print$1}'`</td><td><a href=\"$F.0-req\">$F.0-req</a></td><td><a href=\"$F.0-resp\">$F.0-resp</a></td><td>`wc -c $F.0-clean_resp|awk '{print$1}'`</td><td>---</td><td>---</td></tr>" >> $F.html
for i in `wc -l $F.*.md5.txt|grep .md5.txt|sort -n -r|awk '{print$2}'`; do
  j=`head -1 $i | grep clean_resp`
  k=`echo $j|sed 's/clean_//'`
  test "$k" = "$F.0-resp" || {
    diff -ibwBaNdU 0 $F.0-clean_resp $j | egrep -av '^@|^\+\+\+|^---' > $i.diff.txt
    echo "<tr><td><a href=\"$i.html\">$i</a></td><td><a href=\"${i}-out\">${i}-out</a></td><td>`wc -l $i|awk '{print$1}'`</td><td><a href=\"`echo $k|sed 's/resp/req/'`\">`echo $k|sed 's/resp/req/'`</a></td><td><a href=\"$k\">$k</a></td><td>`wc -c $j|awk '{print$1}'`</td><td><a href=\"$i.diff.txt\">$i.diff.txt</a></td><td>`wc -c $i.diff.txt|awk '{print$1}'`</td></tr>" >> $F.html
    {
      echo ====================================================================
      echo "DIFF $F.0-resp TO $k ($i)"
      cat $i.diff.txt
      echo
    } >> $F.diff.txt
  }
done
echo "</TABLE>" >> $F.html
echo "<hr><b>FUZZING REQUEST OVERVIEW (can be ignored)</b><p>" >> $F.html
echo "<pre>`cat $F.out|grep '^Request'`</pre>" >> $F.html
echo "<hr></body></html>" >> $F.html
echo DONE - HTML output is in $F.html
test `uname -o` = Cygwin && {
  pwd | grep -qi /c/ && echo file:///C:`pwd|sed 's/.*\/c\//\//'`/$F.html
  pwd | grep -qi /c/ || echo file:///C:/cygwin`pwd`/$F.html
}
test `uname -o` = Cygwin || echo file://`pwd`/$F.html

