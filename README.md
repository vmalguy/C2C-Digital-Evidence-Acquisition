# C2C-Digital-Evidence-Acquisition

## Idea
You got a server running in the cloud.
You want to image it for forensic.
Just boot in single user, slice the partitions and send them to a remote cloud storage (S3) service.
End-to-end encryption and compression is in use.

## How to

### Extract data (split)
* reboot your cloud instance in single mode
* source openrc.sh credential
* run split.sh 
* record encryption key and container name in an encrypted form
* wait for the split script to finish... can take 8 hours on a 2To

### recover data (unsplit)

I would recommend using GNU linux OS and a separate directory for each partition. 
You need GPG and ZIP installed. 
Make sure you have twice the amount of space available than the size of the partition you are trying to recover.

* use gen_url to generate the downloadable URL and get this files. This link are valid only XXhours.  
* use the unsplit.sh linux script to recover the data

unplist.sh will ask you for the “encryption key”. 
Partition data will be put in the file name “output” .
Each partition have a log file. You will find sha1 hash of the original partition to control the integrity of the copy.
