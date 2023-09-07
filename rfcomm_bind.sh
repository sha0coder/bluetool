#!/bin/bash
bssid=$1
channel=$2

sudo rfcomm bind 0 $bssid $channel

