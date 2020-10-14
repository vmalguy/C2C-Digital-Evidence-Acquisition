#!/bin/bash

echo -n Dependancy verification :
command -v rclone >/dev/null 2>&1 || ( apt install curl && curl -s https://rclone.org/install.sh | sudo bash )
command -v swift >/dev/null 2>&1 || ( apt install python-swiftclient )
command -v dcfldd >/dev/null 2>&1 || ( apt install dcfldd )
echo Dependancy meet!

if ! test -n "$STY";
 then 
   echo "This is NOT a screen session."
   echo "Use screen -S split to launch this script, exiting."  
   exit 1
fi

if [ -z "$1" ]
  then
    echo "No argument supplied, need to be a partition, exemple : /dev/sdba1"
    fdisk -l|grep "dev"
    exit 1
fi

FILE="$1"
OUTPUT=`echo "$FILE" | tr "/" "_"`
echo Output files will be : $OUTPUT


#create a new fresh SWIFT container
CONTAINER=$OUTPUT_`date +%s`
swift post $CONTAINER
if [ $? -eq 0 ]; then
    echo container is $CONTAINER
else
    echo swift post failed, did you source openrc.sh ?
    exit 1
fi

# Setup rclone base on openstack configuration 
export RCLONE_CONFIG_MYREMOTE_TYPE=swift
export RCLONE_CONFIG_MYREMOTE_ENV_AUTH=true
mkdir -p ~/.config/rclone/ && touch ~/.config/rclone/rclone.conf
SNAME=myremote
SWIFT=${SNAME}:${CONTAINER}

echo -n "starting aquisition at " > $OUTPUT.log
date "+%Y/%m/%d %H:%M:%S" >> $OUTPUT.log

ENCKEY=`openssl rand -base64 16 | colrm 17`
echo "encryption key is "$ENCKEY
echo "transmit it to anyone who need to decypher the data"

#How big we want the chunks to be in bytes. 
# Note that compression will reduce size but encryption will add overhead
# 5000 * 1024 * 1024 = 5G maximum for swift
CHUNKSIZE=$(( 5000 * 1024 * 1024 ))

#Block size for dd in bytes
BS=$(( 4 * 1024 ))

#Convert CHUNKSIZE to blocks
CHUNKSIZE=$(( $CHUNKSIZE / $BS ))

# Skip value for dd, we start at 0
SKIP=0

#Calculate total size of file in blocks
#FSIZE=`stat -c%s "$FILE"`
FSIZE=`blockdev --getsize64 "$FILE"`
SIZE=$(( $FSIZE / $BS ))

#Loop counter for file name
i=0

echo "Using chunks of "$CHUNKSIZE" blocks" >> $OUTPUT.log
echo "Size is "$FSIZE" bytes = "$SIZE" blocks" >> $OUTPUT.log

echo $FILE" is beinig aquired" >> $OUTPUT.log
sha1sum $FILE >> $OUTPUT.log &

while [ $SKIP -le $SIZE ]
do
date "+%Y/%m/%d %H:%M:%S" >> $OUTPUT.log

NEWFILE=$(printf "$OUTPUT.part%03d" $i)
i=$(( $i + 1 ))

echo "Creating file "$NEWFILE" starting after block "$SKIP"" >> $OUTPUT.log
echo "Creating file "$NEWFILE" starting after block "$SKIP""

#this line is the most time consuming (dd + gzip)
dcfldd if="$FILE"  bs="$BS" count="$CHUNKSIZE" skip=$SKIP hash=sha256 sha256log=${NEWFILE}.sha256 conv=noerror,sync errlog=${NEWFILE}.errlog | gzip -4 > ${NEWFILE}.gz 

gpg --yes --batch --passphrase=${ENCKEY} --output ${NEWFILE}.gz.aes --symmetric --cipher-algo AES256  ${NEWFILE}.gz 
rm ${NEWFILE}.gz &

rclone copy --progress ${NEWFILE}.gz.aes $SWIFT 

echo -n ${NEWFILE}  >> $OUTPUT.log
cat ${NEWFILE}.sha256 >> $OUTPUT.log && rm ${NEWFILE}.sha256
echo -n ${NEWFILE} >> $OUTPUT.log
cat ${NEWFILE}.errlog >> $OUTPUT.log && rm ${NEWFILE}.errlog
sha1sum ${NEWFILE}.gz.aes >> $OUTPUT.log
rm ${NEWFILE}.gz.aes &


SKIP=$(( $SKIP + $CHUNKSIZE ))
done

date "+%Y/%m/%d %H:%M:%S" >> $OUTPUT.log
echo "Finished" >> $OUTPUT.log
rclone copy $OUTPUT.log $SWIFT

echo "encryption key is "$ENCKEY
echo "transmit it to anyone who want to decypher the data"
echo "Finished"

