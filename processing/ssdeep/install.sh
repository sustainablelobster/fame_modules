#!/usr/bin/env sh
SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

docker build -t fame/ssdeep $SCRIPTPATH/docker
