#!/bin/bash

PATH=/home/alireza/ghost/pin-3.27-98718-gbeaa5d51e-gcc-linux/source/tools/ManualExamples/

# running agent SOL
$mypath/../../../pin -t $mypath/obj-intel64/inscount0.so -- ./bazel-bin/agent_sol
