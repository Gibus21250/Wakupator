# Wakupator

Simple and minimalist machine awakener using IP spoofing for the good cause.

## Table of Contents
1. [Overview](#overview)
2. [Precautions](#precautions)
    - [Local machine side](#local-machine-side)
    - [Wakupator side](#wakupator-side)
      - [Required](#Required)
      - [Recommended](#Recommended)
3. [Get Started](#get-started)
    - [Compile Project](#compile-project)
    - [Pre-compiled Binaries](#pre-compiled-binaries)
4. [How to Use](#how-to-use)
      - [Logs](#logs)
5. [Register a machine](#register-a-machine)
   - [Example JSON](#example-json)
6. [Real example](#Real-example)
   - [Context](#Context)
   - [Launch Wakupator](#launch-wakupator)
   - [Prepare the JSON](#prepare-the-json)
   - [Automate machine registration](#automate-machine-registration)
   - [Register the machine](#register-the-machine)
   - [Final test](#final-test)
7. [Contribute](#contributing)
8. [License](#license)
9. [Third-party](#Third-party-libraries)

## Overview

This service allows other machines on the **same LAN** to be woken up when specific traffic is detected.
Before shutdown, machines can request to spoof their IP address(es) and associate one or more ports to each of them.
When network traffic is detected, the registered machine is woken up via a **Wake-on-LAN** (IEEE 802.3) magic packet.

The main goal of this project is to **reduce energy consumption** by **sacrificing availability**.

This is ideal for home servers, small infrastructure which are hosting services that are not in use 24 hours a day.

___

## Precautions

Your router or L3 OSI hardware should not have static IP/MAC bindings on IP addresses that could be spoofed by Wakupator.

When a machine needs to register with Wakupator, it should do so just before shutting down.

On the client side and in some cases, the first connection attempt may result in a timeout or reset, **depending on the machine boot time,
and the behavior of the service**.

### Local machine side

The machine must be able to be started by a magic Wake-On-LAN packet (IEEE 802.3). You need to enable this in your BIOS/UEFI,
as well as in your operating system.

If you want to monitor an `IPv6` address and the machine can be started manually, you should definitely disable duplicate IPv6 address detection on it.

###### This is because the kernel of the machine, when configuring the IP stack, performs ARP and NS operations that Wakupator detects as soon as possible. But sometimes there is too much delay (of the order of a few milliseconds) between the removal of spoofed IP addresses and the update of the IP stack of the kernel of the machine hosting Wakupator, which will then respond that IPv6 is already in use.

You can set this with the command:

`````bash
sysctl -w net.ipv6.conf.{interface/all}.accept_dad=0
`````
Replace *interface* with the name of the relevant interface.

### Wakupator side

#### Required

Wakupator needs to be executed by a user who have these permissions and have access to these commands:

- The command `ip` from `iproute2` to add and delete spoofed IPs.
- The command `sysctl` to temporally disable Duplicate Address Detection for IPv6 spoofing.
- Capability `CAP_NET_RAW` to create raw sockets.

**_Running Wakupator as root will grant it the necessary permissions._**

#### Recommended

These recommendations do not prevent Wakupator from working, but their application helps improve the client experience and avoid certain side effects.

1. Wakupator should not be exposed outside your local network, and especially not to the Internet.

2. Ideally, you should bind all services hosted on the Wakupator's machine on **real** host IP:
   - Services bound to "0.0.0.0" or "::" may use a spoofed IP address for outbound communications. (seen with IPv6)
   - This prevents the client from establishing a connection with services hosted on the host (example with SSH) using a spoofed IP, 
   which will be quickly closed. (because Wakupator will delete the IP simultaneously, and thus the OS will cut the connection 
   to the client)

3. In addition to the previous recommendation, you should configure the firewall to only accept packets destined for the 
   host's real IP addresses, and reject all others. This prevents the host from responding with RST packets, which would likely 
   cause the client to abandon the connection attempt after receiving it.

The idea is to prevent services on Wakupator's machine from mixing with those normally hosted by the spoofed machines running 
on the same ports. Furthermore, it is necessary to prevent the machine from responding with a packet, even an RST, which 
could close the client's connection attempt, and also unintentionally refresh the OS's ARP/NDS cache if it is on the same LAN.

With these rules, when packets are dropped, the client will simply resend connection initiation packets periodically 
(until a timeout), so if the machine actually hosting the service starts up quickly enough, the client will only see high latency, 
but all this will be done in an opaque way for the client!

This is an example of firewall rules:
````bash
table ip6 global {
        chain input {
                [...]
                tcp dport 13717 ip6 saddr 2001:0db8:3c4d:c202:1::/80 accept #only accept packet from same LAN for Wakupator
                tcp dport 22 ip6 daddr 2001:0db8:3c4d:c202:1::1234 accept #only accept SSH(22) packet for real host IPv6
                [...]
        }
}
table ip global4 {
        chain input {
                [...]
                tcp dport 13717 ip saddr 192.168.0.0/24 accept #only accept packet from same LAN for Wakupator
                tcp dport 22 ip daddr 192.168.0.37 accept #only accept SSH(22) packet for real host IP
                [...]
      }
}

````
___

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

You can download precompiled binaries from the release tab.

## How to use

To run Wakupator, bind it to an IP address using the -H (or --host) option:

``wakupator -H <IPv4/v6>``

You have some options to custom Wakupator behavior:

| Option                           | Description                                                                                           |
|----------------------------------|-------------------------------------------------------------------------------------------------------|
| `-H, --host <ip_address>`        | **(Required)** Set the host IP address. (IPv4 or IPv6)                                                |
| `-p, --port <port_number>`       | Set the port number (0-65535, **DEFAULT**: 13717)                                                     |
| `-if, --interface-name <name>`   | Specify the network interface name. (**DEFAULT**: eth0)                                               |
| `-nb, --number-attempt <number>` | Set the number of Wake-On-LAN attempts. (**DEFAULT**: 3)                                              |
| `-t, --time-between-attempt <s>` | Set the time in seconds between attempts. (**DEFAULT**: 30)                                           |
| `-kc, --keep-client <0\|1>`      | Keep the client monitored if he doesn't start after <-nb> attempt(s). (0: NO, 1: Yes, **DEFAULT**: 1) |


Examples:
```bash
wakupator -H 192.168.1.37 -e eth2 -p 3717
wakupator -H 192.168.0.37 -p 1234 -if eth2 -nb 5 -t 15 -kc 1
```

### Logs

If you want to test Wakupator, you can execute the Debug compiled version to see logs in your terminal.

For production use, it's recommended to run Wakupator (Release compiled version) as a service. (An example is provided in `example/host`)

Logs can then be viewed using:
```
journalctl -f -u yourServiceName
```
Or:
```bash
systemctl status yourService
```
___

## Register a machine

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
___

## Real example

### Context

In my case, my Raspberry PI (`raspberrypi`) runs Wakupator. I have another machine (`tartiflette`) with some services 
like a Minecraft server bind on a IPv6 address (2001:0db8:3c4d:4d58:1::2222).

I don't want that machine to run 24/7, wasting electricity when it's unused 80% of the time.

My goal with Wakupator:

- Wake up the machine (`tartiflette`) when traffic is detected on:
  - IP `2001:0db8:3c4d:4d58:1::2222` on ports 25565 (Minecraft) or 22 (SSH).
  - IP `192.168.0.37` on port 22 (SSH).
- It is also likely that the machine is started manually, but Wakupator will detect it automatically.

### Launch Wakupator

First, we need to launch `Wakupator` on a machine, for my part it is the `raspberrypi` and I will launch the `release` version.

**Don't forget to allow the port (default: 13717) on the host's firewall if necessary**

On `raspberrypi`, we can monitor logs using:

```bash
journalctl -f -u wakupator
or
systemctl status wakupator
```

At this point, with Wakupator running, you should see this log:

```
Oct 21 10:43:13 raspberrypi Wakupator[65081]: Ready to register clients!`
```

### Prepare the JSON

After, we need to retrieve the MAC address of the related interface on the machine `tartiflette`.

For this, you can use the command `ip link`:

```bash
    nathanj@tartiflette:~$ ip link
    [...]
    2: enp4s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether d8:cb:8a:39:be:a1 brd ff:ff:ff:ff:ff:ff
    # here ->  ^^^^^^^^^^^^^^^^^
```

And now, for each IP and associated port(s) of services that we want, we need to construct a JSON object.

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

### Automate machine registration

I will create a simple Python script to send this JSON payload.

I put the Python script in `/etc/wakupator/register_to_wakupator.py`

Finally, I will create a service on `tartiflette` to execute this Python script just before shuts down.

I put the service file in `/etc/systemd/system/register.service`.

All related files are in `example/machine/`.

Then execute these commands to enable the service: 
```bash
root@tartiflette:/home/nathan# systemctl daemon-reload
root@tartiflette:/home/nathan# systemctl enable register.service

#Verify the status
root@tartiflette:/home/nathan# systemctl status register
 register.service - Register the system to Wakupator
     Loaded: loaded (/etc/systemd/system/register.service; enabled; preset: enabled)
     Active: inactive (dead) # <-- OK because the script will be executed just before the machine shuts down.
```

To resume, when the machine shuts down, a Python script that sends the JSON payload to Wakupator is automatically executed by the service.

### Register the machine

To register the machine, it needs to shut down. You can achieve that by executing the command `/sbin/shutdown now`,
or simply by pressing the shutdown button.

Ideally you should design a custom script that shuts down the machine under certain conditions. (Mainly no network activity)
But for this test, we're going to shut down the machine manually.

After shutting down the machine, you should see a log similar to this on the host, `raspberrypi`:

```
Oct 21 10:45:32 raspberrypi Wakupator[65081]: New client registered: [d8:cb:8a:39:be:a1]
                                                      IP: 2001:0db8:3c4d:4d58:1::2222, port: [25565, 22]
                                                      IP: 192.168.0.37, port: [22]
Oct 21 10:45:33 raspberrypi Wakupator[65081]: Monitoring started.
```

### Final test

Now, test Wakupator's behavior by triggering one of your rules. I'll test it by initiating a TCP connection to IP 
`192.168.0.37` on port 22 (SSH).

You can also use `netcat` to simulate a TCP connection on a specific port:

````bash
nc -zv 192.168.0.37 22
````

The machine should start up immediately, and Wakupator will log every attempt and the boot time of the machine.

A log will appear on the host like this:

````
Oct 21 10:49:50 raspberrypi Wakupator[65081]: Client [d8:cb:8a:39:be:a1]: traffic detected.
Oct 21 10:49:50 raspberrypi Wakupator[65081]: Client [d8:cb:8a:39:be:a1]: Wake-On-Lan sent. (attempt 1)
Oct 21 10:50:05 raspberrypi Wakupator[65081]: Client [d8:cb:8a:39:be:a1]: the machine has been started successfully. (15.77s)
Oct 21 10:50:05 raspberrypi Wakupator[65081]: Client [d8:cb:8a:39:be:a1] has been retired from monitoring.
````

You can also start the machine manually (by pressing the power button, or with a manual WoL packet), and Wakupator will see it, 
and log this message:

````
Oct 21 10:55:22 raspberrypi Wakupator[65081]: Client [d8:cb:8a:39:be:a1]: the machine appears to have been started manually.
Oct 21 10:55:22 raspberrypi Wakupator[65081]: Client [d8:cb:8a:39:be:a1] has been retired from monitoring.
````

## Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue on the repository.

___

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
___

## Third-party libraries

This project uses the following third-party libraries:

- [**cJSON**](https://github.com/DaveGamble/cJSON) - A JSON parsing library in C.
   - License: MIT
   - You can find the full license text in the file `lib/cJSON/LICENSE.txt`.