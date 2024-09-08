# Wakupator

## Overview

This project provide a service that allows servers on the same local network to
request the spoofing of a list of IP addresses and associate one or more
ports per IP address.

## Objective

The main goal of this project is to optimize energy consumption by sacrificing availability.
When the service receives traffic initially destined for the spoofed IPs, it automatically wakes up
the original server and forward the traffic to it while booting.

# How to use
Wakupator need the capability CAP_NET_RAW, and use the tools ``iproute2`` to add IP on the host, which need perms too.

You can set the capabilities needed by Wakupator:

`````bash
sudo setcap cap_net_raw,cap_net_admin=eip wakupator
`````

or directly execute as root.

## Register a server to wakupator

The server accept and reply a JSON format

Here are valid example:

`````json
{
    "mac": "be:ef:fa:ce:c0:de",
    "monitor": [
        {
            "ip": "191.168.0.12",
            "port": [25565]
        }
    ]
}
`````

`````json
{
    "mac": "be:ef:fa:ce:c0:de",
    "monitor": [
        {
            "ip": "191.168.0.41",
            "port": [22, 25565]
        },
        {
          "ip": "2001:0db8:3c4d:c202:1::2222",
          "port": [1234]
        }
    ]
}
`````

When the server ask to be registered, it replies with a message. if it is different from `OK.`, it means that the host
doesn't have registered the client, and details are contained in the reply.

Wakupator cannot register a MAC address that has been already registered. Same for an IP.


