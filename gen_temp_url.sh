# need openrc.sh and .rclone.conf
#apt install python-swiftclient curl
#curl https://rclone.org/install.sh | sudo bash

echo -n Dependancy verification :
command -v rclone >/dev/null 2>&1 || ( apt install curl && curl -s https://rclone.org/install.sh | sudo bash )
command -v swift >/dev/null 2>&1 || ( apt install python-swiftclient )
echo Dependancy meet!

if [ -z "$1" ]
  then
    echo "No argument supplied, need to be a container name, exemple : 1697438492"
    exit 1
fi

# Setup rclone base on openstack configuration
export RCLONE_CONFIG_MYREMOTE_TYPE=swift
export RCLONE_CONFIG_MYREMOTE_ENV_AUTH=true
mkdir -p ~/.config/rclone/ && touch ~/.config/rclone/rclone.conf
SNAME=myremote
SWIFT=${SNAME}:${CONTAINER}


#provide (first) URL key
URLKEY=`swift stat|grep Temp-Url-Key| head -n 1| awk '{print $NF}'`
#provide OS_STORAGE_URL
`swift  auth`
URI=`echo $OS_STORAGE_URL| cut -d"/" -f 4-`
DOMAIN=`echo $OS_STORAGE_URL| cut -d"/" -f -3`

for file in `swift list $1`
  do
    URL=`swift tempurl GET 604800 /${URI}/$1/$file  ${URLKEY}`
    echo wget --content-disposition -nc \"${DOMAIN}${URL}\"
  done

