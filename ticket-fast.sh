#!/bin/bash
pipe=$(mktemp -u)

mkfifo $pipe

./diff-extract.py $1 $pipe &
./ticket-extract.py $pipe $2

rm $pipe
