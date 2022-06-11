#!/bin/bash

#listing file to unsplit
FLIST=`ls -tr1 *.part*`
#output file name
OUTPUT=`ls *log|cut -d'.' -f1`
#remove any previous output file
test -f $OUTPUT && rm -i $OUTPUT

#integrity check
read -r -p "Do you want to check file integrity? [y/N] " response
case "$response" in
    [yY][eE][sS]|[yY])
        sha1sum -c `ls *.log`
        ;;
    *)
        echo "Integrity check skipped";
        ;;
esac

echo "enter decryption key"
read ENCKEY

# decypher and concat
for F in $FLIST
do
  gpg --yes --batch --passphrase=${ENCKEY} --decrypt ${F} | gunzip >> $OUTPUT
done

sha1sum $OUTPUT > $OUTPUT.sha1 &
echo "sha1sum of the result is being process in the background, you can wait for additional verification or exit this script and manualy check integrity later in $OUTPUT.sha1"
if cat $OUTPUT.sha1 |cut -d" " -f1|xargs -d '\n' -I hash grep hash $OUTPUT.log
then
        echo Integrity OK
else
        echo log file integrity recorded is not matching your result $OUTPUT
fi
