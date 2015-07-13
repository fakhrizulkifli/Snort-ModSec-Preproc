#!/bin/bash 
cmd=$(make;sudo make install;sudo snort -c snort.lua -i eth0 -A fast)

while read -r line; do
    grep -i ":/"
done <<< "$cmd"
