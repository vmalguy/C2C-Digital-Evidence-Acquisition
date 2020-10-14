#!/bin/bash

FLIST=`ls -tr1 *.part*`

OUTPUT="output"
rm -i $OUTPUT

echo "enter decryption key"
read ENCKEY

for F in $FLIST
do
  gpg --yes --batch --passphrase=${ENCKEY} --decrypt ${F} | gunzip >> $OUTPUT
done

sha1sum $OUTPUT > $OUTPUT.sha1 &
echo "sha1sum of the result is being process in the background"
echo "cat $OUTPUT.sha1"
