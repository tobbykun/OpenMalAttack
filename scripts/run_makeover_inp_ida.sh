#!/usr/bin/env bash

BIN=../dataset/malware/040f0360b1822ecd23fdcef06b48049a296e6fe07f0f26faf85f90dc03aca1bc
IDA_BIN=XXX/idaq64
IDA_SCRIPT=../ThirdParty/MakeOver/enhanced-binary-randomization/orp/inp_ida.py
LOG=/tmp/ida.log

"$IDA_BIN" -A -S"$IDA_SCRIPT" -L"$LOG" "$BIN"