# Wakupator

Simple and minimalist machine awakener using IP spoofing for the good cause.

## Table of Contents
1. [Overview](#overview)
2. [Precautions](#precautions)
    - [Client Side](#client-side)
    - [Wakupator Side](#wakupator-side)
3. [Important Notes](#important)
4. [Get Started](#get-started)
    - [Compile Project](#compile-project)
    - [Pre-compiled Binaries](#pre-compiled-binaries)
    - [How to Use](#how-to-use)
      - [Logs](#logs)
5. [Register a Client](#register-a-client)
   - [Example JSON](#example-json)
6. [Typical example](#Typical-example)
   - [Context](#Context)
   - [Registering the client](#register-the-client)
   - [Final test](#final-test)
7. [Contribute](#contributing)
8. [License](#license)
   - [Third-party](#Third-party-libraries)

## Overview

This service enables other servers on the same local network to request the spoofing of their IP address(es) 
and associate one or more ports with each. When network traffic is detected, the registered machine is 
awakened via an IEEE 802.3 packet (Wake-on-LAN packet).

The main goal of this project is to reduce energy consumption by sacrificing availability.

This is ideal for home servers, small infrastructure which are hosting services that are not in use 24 hours a day.

___

## Precautions

Your router or L3 OSI hardware should not have static  IP/MAC bindings on IP addresses that could be spoofed by Wakupator.

When a client needs to register with Wakupator, it should do so right before shutting down.

### Client side

The client machine must be able to be started by IEEE 802.3 packet (Wake On Lan). You need to enable this in your BIOS/UEFI,
as well as in your operating system. 

You can do your tests once this is done, by manually starting your machine with the wakeonlan tool on linux for example.

### Wakupator side

Wakupator needs to be executed by a user who have these permissions and have access to these commands:

- The command `ip` from `iproute2` to add and delete spoofed IPs.
- The command `sysctl` to temporally disable Duplicate Address Detection for IPv6 spoofing.
- Capability `CAP_NET_RAW` to create raw sockets.

**_Running Wakupator as root will grant it the necessary permissions._**

Ideally, you should bind all _real_ services hosted on the Wakupator's machine on a real host IP.
Services bound to ``0.0.0.0`` or ``::`` could use a spoofed IP for outgoing communications. (mainly in IPv6)

___
## Important

Currently, if a machine is registered to Wakupator, **do not start the machine manually**.
Wakupator won't know, and there will be an IP duplication on your local network.

As a result, your machine might become inaccessible. To fix this, you can restart Wakupator manually.

### I'm currently working to find a viable solution to this problem.

## Get started

### Compile project

Clone the project, go to the folder of the freshly cloned project, and generate compile files with CMake:
`````bash
cmake -B"build"
`````
And then, go to the folder `build`, and launch the compilation with your tools, usually on linux it is MakeFiles:

`````bash
make
`````

### Pre-compiled binaries

You can download everything you need download in the release tab.

### How to use

To use Wakupator, bind it to an IP address using the -H option:

``wakupator -H <IPv4/v6>``

By default:
- Wakupator uses the `eth0` interface to send IEEE 802.3 packets and monitor traffic. You can change this with `-e 'interfaceName'`.
- Wakupator listens on port `13717`, but you can change it with the option `-p <port>`

Example:
```bash
wakupator -H 192.168.1.37 -e eth2 -p 3717
```

#### Logs

If you want to test Wakupator, you can execute the Debug compiled version to see logs in your terminal.

For production use, it's recommended to run Wakupator as a service. (An example is provided in `example/host`)
Logs can then be viewed using:
```
journalctl -f -u yourServiceName
```
Or:
```bash
systemctl status yourService
```

## Register a client

To register a machine to Wakupator, establish a TCP connection to Wakupator and send a JSON payload. 

Wakupator will start monitoring and spoofing IPs after responding with `OK.`. Any other response indicates an error and 
Wakupator will not proceed.

**The client need to register itself just before shutting down**, an example of a systemd service and a python script
is available in `example/machine`.

### Example JSON

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

## Typical example

### Context

In my case, my Raspberry PI runs Wakupator. I have another machine with some services like a Minecraft server bind on a IPv6 address.

I don't want that machine to run 24/7, wasting electricity when it's unused 80% of the time.

My goal with Wakupator:
- Wake up the machine when traffic is detected on IP `2001:0db8:3c4d:4d58:1::2222` on ports 25565 (Minecraft) or 22 (SSH).
- Wake up the machine for IP `192.168.0.37` on port 22 (SSH).

To retrieve the machine's MAC address, you can use `ip a`:

```bash
2: enp4s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether d8:cb:8a:39:be:a1 brd ff:ff:ff:ff:ff:ff # <- here (the first one on the left side, not the broadcast one)
    inet 192.168.0.37/24 brd 192.168.0.255 scope global enp4s0
    inet6 2001:0db8:3c4d:4d58:1:2222/80 scope global
       valid_lft forever preferred_lft forever
    [...]
```

Here's how the JSON looks:

`````json
{
    "mac": "d8:cb:8a:39:be:a1",
    "monitor": [
        {
          "ip": "2001:0db8:3c4d:4d58:1::2222",
          "port": [25565, 22]
        },
        {
          "ip": "192.168.0.37",
          "port": [22]
        }
    ]
}
`````

So, when the machine shuts down, a Python script executed by a service will register the machine with Wakupator.

You can find the scripts used in `example/machine/`.
There's also an example of a systemd service file to launch Wakupator in `example/host`.

**Don't forget to open the port (default: 13717) on the host's firewall if necessary**

### Register the client

On the host, I monitor logs using:

```bash
journalctl -f -u wakupator
```

At this point, with Wakupator running, you should see this log:

```
Sep 30 10:42:47 raspberrypi Wakupator[10226]: Ready to register clients!`
```
Shutdown the machine with the command `/sbin/shutdown now`.

After shutting down the machine, you should see a log similar to this on the host:

```
Sep 30 10:59:57 raspberrypi Wakupator[10226]: New client registered: [d8:cb:8a:39:be:a1]
                                                      IP: 2001:0db8:3c4d:4d58:1::2222, port: [25565, 22]
                                                      IP: 192.168.0.37, port: [22]
```

### Final test

Now, test Wakupator's behavior by triggering one of your rules. I'll test it by initiating a TCP connection to IP 
`192.168.0.37` on port 22 (SSH).

You can also use `netcat` to simulate a TCP connection on a specific port:

````bash
nc -zv 192.168.0.37 22
````

The machine should start up immediately, and a log will appear on the host like this:

````
Sep 30 11:03:20 raspberrypi Wakupator[10226]: Client d8:cb:8a:39:be:a1: traffic detected, woken up.
````

On the client side, the first connection attempt may result in a timeout or reset, **depending on the machine's boot time.**

# Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue on the repository.

# License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Third-party libraries

This project uses the following third-party libraries:

- [**cJSON**](https://github.com/DaveGamble/cJSON) - A JSON parsing library in C.
   - License: MIT
   - You can find the full license text in the file `lib/cJSON/LICENSE.txt`.