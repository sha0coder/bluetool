#!/bin/bash
bssid=$1

sudo rfcomm connect 0 $bssid

