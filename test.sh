#!/bin/bash

data=$(cat -)
IFS=, packet=(${data//1[4,6,7]0303/,})

echo "${packet}"
