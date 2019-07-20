#!/bin/bash

gcc dnsintrcept.c -o dnsintrcept
gcc client.c -o client

sudo ./dnsintrcept
