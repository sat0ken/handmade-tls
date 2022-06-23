#!/bin/bash

data=$(cat resp.bin)
IFS=, packet=(${data//1[4,6,7]0303/,})

for p in "${packet[@]}"; do
    echo $p
done
