# need source openrc.sh
# apt install python-swiftclient wget
#curl https://rclone.org/install.sh | sudo bash

PROVIDER="storage.us-east-va.cloud.ovh.us"
AUTH="ENTER_YOUR_AUTH_URL"

for file in `swift list $1`
  do
    URI=`swift tempurl GET 604800 /v1/${AUTH}/$1/$file  MYKEY`
    echo wget --content-disposition -nc \"https://${PROVIDER}${URI}\"
  done
