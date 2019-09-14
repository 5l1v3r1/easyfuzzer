#!/bin/bash

test -z "$2" -o "$1" = "-h" && {
  echo "Syntax: $0 [-a] [-p] TARGET WEBSCARAB_DIRECTORY"
  echo "TARGET: the target to attack, eg. \".customer.com\""
  echo "WEBSCARAB_DIRECTORY: the data directory of webscarab"
  echo "starts easyfuzzer-proxy.pl on requests and runs them through"
  echo "prepare4easyfuzzer, easyfuzzer and easyfuzzer.diff"
  echo "Option -a: by default, every request URL is fuzzed just one time."
  echo "To fuzz an URL everytime, use this option."
  echo "Option -p: by default, only requests after starting this tool"
  echo "will be fuzzed. However if PREVIOUS should be fuzzed (old, existing"
  echo "requests) use this option."
  exit 1
}


ALL=""
PREV=""

test "$1" = "-a" && {
  ALL=-a
  shift
}
test "$1" = "-p" && {
  PREV=yes
  shift
}
test "$1" = "-a" && {
  ALL=-a
  shift
}

TARGET=$1

cd "$2" || {
  echo "Directory does not exist: $2"
  exit 1
}
test -d conversations && cd conversations

echo "Starting, watching in `pwd`"
COUNT=1;

test "$PREV" = "yes" || {
  FILE="$COUNT-request"
  while [ -f $FILE ]; do
    COUNT=`expr $COUNT + 1`
    FILE="$COUNT-request"
  done
  echo "Waiting for $FILE (use the -a option to fuzz already existing files)"
}

while : ; do
  FILE="$COUNT-request"
  FILE1="`expr $COUNT + 1`-request"
  FILE2="`expr $COUNT + 2`-request"
  FILE3="`expr $COUNT + 3`-request"
  FOUND=""
  while [ ! -f $FILE ]; do
    if [ -f $FILE1 ]; then
      if [ ! -f $FILE ]; then
        FILE=$FILE1
      fi
    else
      if [ -f $FILE2 ]; then
        if [ ! -f $FILE ]; then
          if [ -f $FILE1 ]; then
            FILE=$FILE1
          else
            FILE=$FILE2
          fi
        fi
      else
        if [ -f $FILE3 ]; then
          if [ ! -f $FILE ]; then
            if [ -f $FILE1 ]; then
              FILE=$FILE1
            else
              if [ -f $FILE2 ]; then
                FILE=$FILE2
              else
                FILE=$FILE3
              fi
            fi
          fi
        fi
      fi
    fi
    test -e $FILE || sleep 1;
  done
  COUNT=`echo $FILE|sed 's/-request//'`
  head -1 $FILE | grep -q $TARGET && FOUND=1
  grep -i "^host: " $FILE | grep -q $TARGET && FOUND=1
  test "$FOUND" = 1 && {
    echo "Running: easyfuzzer-proxy.pl $ALL $FILE"
    easyfuzzer-proxy.pl $ALL $FILE
  }
  test "$FOUND" = 1 || {
    echo "Request $FILE is not concerning $TARGET, ignoring request"
  }
  COUNT=`expr $COUNT + 1`
done
