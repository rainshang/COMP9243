#!/bin/bash
PROCESSES="dsm client";
for i in $(seq -w 0 09);do
    echo "#### vina$i";
    ssh vina$i "ps aux | grep $USER;
    killall -u $USER $PROCESSES";
done
