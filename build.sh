#!/bin/sh
exec gcc -O2 -Wall `pkg-config --cflags-only-I wireshark` -shared -o dlms.so dlms.c -s
#exec gcc -O2 -Wall -I/usr/include/wireshark -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -shared -o dlms.so dlms.c -s
