#!/bin/sh
termuxUid="$(dumpsys package com.termux | grep uid | awk 'NR==1{print $1}' | cut -d '=' -f2)"
nohup chown -R $termuxUid:$termuxUid $(pwd) >/dev/null 2>&1 &
chmod -R 0755 $(pwd)
rm -f src/*.bak  *.bak