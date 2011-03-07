#!/bin/bash
if [ $# -lt 2 ]
then
  echo "VX Antidote - v.0.1"
  echo "$0 <mac> <pcap file>"
  exit
fi

MAC=$1
FILE=$2

tshark -R "(wlan.sa != ${MAC}) && (wlan.da != ${MAC})" -r $FILE  -w clean.cap
aircrack clean.cap

