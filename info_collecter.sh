#!/bin/bash

read -p "Enter IP : " IPADDR

# HOSTNAME=$(host ${IPADDR})
# echo $HOSTNAME
echo " "
echo "--------------------------------------------------"
echo " "
arping -c 1 $IPADDR > /dev/null 2>&1
if [ $? -eq 0 ]
then
    echo "Link Layer ALIVE"
else
    echo "Link Layer NOT ALIVE"
fi


ping -c 1 "$IPADDR" > /dev/null 2>&1
if [ $? -eq 0 ]
then 
    echo "NETOWRK LAYER ALIVE"

else
    echo "NETWORK LAYER NOT ALIVE"
fi

nc -zv ${IPADDR} 80

