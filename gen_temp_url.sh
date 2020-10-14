# need source openrc.sh
# apt install python-swiftclient wget

PROVIDER="storage.us-east-va.cloud.ovh.us"

for file in `swift list $1`
  do
    URI=`swift tempurl GET 604800 /v1/AUTH_651a5b8b45764713a1c999ed818fbb12/$1/$file  MYKEY`
    echo wget -nc \"https://${PROVIDER}${URI}\"
  done
