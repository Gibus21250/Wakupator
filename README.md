# Wakupator

Lightweight, minimal dependencies and non-intrusive machine awakener service using IP spoofing for the good cause.

## Table of Contents
1. [Introduction](#introduction)
   - [Overview](#overview)
   - [Advantages](#advantages)
   - [Limitations](#limitations)

2. [Precautions](#precautions)
   - [Client machine side](#client-machine-side)
   - [Wakupator host side](#wakupator-host-side)
   - [Recommendations](#recommendations)

3. [Get Started](#get-started)
   - [Compile Project](#compile-project)
   - [Pre-compiled Binaries](#pre-compiled-binaries)

4. [How to Use](#how-to-use)
   - [Launch Wakupator](#launch-wakupator)
   - [Register a Machine](#register-a-machine)

5. [Example](#example)
   - [Context](#context)
   - [Launch Wakupator](#launch-wakupator)
   - [Prepare the JSON](#prepare-the-json)
   - [Automate Machine Registration](#automate-machine-registration-during-shutdown-process)
   - [Register the Machine](#register-the-machine)
   - [Final Test](#final-test)

6. [Contributing](#contributing)

7. [License](#license)

8. [Third-party Libraries](#third-party-libraries)

## Introduction

### Overview

This service allows other machines on the **same LAN** to be woken up when specific traffic is detected.
Before shutdown, machines can request to spoof their IP address(es) and associate zero or more ports to each of them.
When network traffic is detected, the registered machine is woken up via a **Wake-on-LAN** (IEEE 802.3) magic packet.

The main goal of this project is to **reduce energy wasting** by **sacrificing availability**.

This is ideal for home servers, small infrastructure which are hosting services that are not in use 24 hours a day.

### Advantages

- **No firewall configuration required**  
  Wakupator reads packets before they reach the host firewall or local services.

- **Works with any IP-based service**  
  Wakupator does not depend on application-layer protocols and can wake machines based on low-level network traffic.

- **Designed for self-hosted environments**  
  Lightweight, minimal dependencies, non-intrusive and easy to integrate into an existing network.
___

### Limitations

- **Sensitive to unsolicited traffic and bot scans**  
  Services exposed to the internet, especially HTTP/HTTPS or IPv4, may receive frequent scans.  
  These packets can trigger Wakupator and cause machines to wake up more often than expected.

### Mitigations

Some strategies to reduce unwanted wake-ups:

- Filter or block bot traffic higher in your network (router or hardware firewall)

## Precautions

Wakupator relies on raw network traffic and IP spoofing. To ensure correct operation, please follow these precautions.

- Your router or L3 hardware **must** not have static IP/MAC bindings on IP addresses that could be spoofed by Wakupator.
- When a machine registers with Wakupator, it must do so shortly before shutdown.
- On the user side, when accessing a stopped service, the first connection attempt may time out or reset.
It depends on the machine's startup time and the service's behavior.


### Client machine side

The monitored machine must support Wake-On-LAN (IEEE 802.3). Enable this feature in both BIOS/UEFI and the operating system.

> [!IMPORTANT]
> If you plan to monitor an `IPv6` address and the machine can be started manually, you **must** disable Duplicate Address Detection (DAD) on the client's machine:

`````bash
sysctl -w net.ipv6.conf.{interface/all}.accept_dad=0
`````
Replace `{interface/all}` with the name of the relevant interface (e.g., `eth0`), or use `all` to apply globally.

#### Why disabling DAD is necessary?

When the monitored machine boots manually, it initializes its network interface and sends ICMPv6 Neighbor Solicitation probes to check if its IP is already in use. 
As Wakupator is running simultaneously, the Linux kernel on the host might respond to these probes before Wakupator 
finishes removing spoofed IPs, causing the machine to mark its address as a duplicate. Disabling DAD prevents this race condition.

### Wakupator host side

#### Required

Wakupator requires the following capabilities to run:

- Capability `cap_net_raw` to create raw sockets.
- Capability `cap_net_admin` to manage IP on the machine.

**You can add these capabilities with the command:**
`````bash
sudo setcap cap_net_raw,cap_net_admin+eip /path/to/wakupator
`````

Alternatively, if you run Wakupator as a service, you can assign capabilities as shown in `example/host/wakupator.service`

#### Recommendations

These recommendations improve reliability and reduce side effects but are not strictly required:

1. **Keep Wakupator internal**  
   Only machines inside the host’s LAN should be allowed to register. Do not expose Wakupator to the Internet.

2. **Bind host services to real IPs**  
   Avoid binding host services to `0.0.0.0` or `::`, which can conflict with spoofed IPs.  
   Example: SSH on port 22 should bind only to the host’s actual IP.

3. **Firewall rules**  
   Accept only packets destined for the host’s real IPs and drop all others. This prevents unwanted RST packets and conflicts with spoofed IPs.

> [!NOTE]
> These measures prevent the host machine from accidentally responding to clients on spoofed IPs, which could otherwise close connections or refresh network caches.

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

Clone the project, go to the folder of the freshly cloned project, and generate build files with CMake:
`````bash
cmake -B"build" -DCMAKE_BUILD_TYPE=Release
cmake --build build
`````
And then, the executable is located in `build/wakupator`.

### Pre-compiled binaries

You can download precompiled binaries from the release tab.

## How to use

### Launch Wakupator

To run Wakupator, specify the host IP address using the `-H` (or `--host`) option:

``wakupator -H <IPv4/v6>``

For testing, you can run Wakupator manually.
Make sure to set the required capabilities as described in the `Required` section.

For production, it is recommended to run Wakupator as a service.

**Service example:**
```
[Unit]
Description=Wakupator server
After=network-online.target

[Service]
Type=simple

StandardOutput=journal
StandardError=journal

User=wakupator              #Verify user
Group=wakupator             #Verify group

AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

ExecStart=/path/to/wakupator -H 2001:0db8:3c4d:4d58:1::1234 #Change to your IPv4/IPv6 and verify path

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/wakupator

Restart=on-failure
TimeoutStopSec=300

[Install]
WantedBy=multi-user.target
```
An example systemd service is provided in `example/host/wakupator.service`.

You can customize Wakupator behavior using the following options

| Option                           | Description                                                                                                 |
|----------------------------------|-------------------------------------------------------------------------------------------------------------|
| **(Required)**                   |                                                                                                             |
| `-H, --host <ip_address>`        | Set the host IP address. (IPv4 or IPv6)                                                                     |
| General parameters               |                                                                                                             |
| `-p, --port <port_number>`       | Set the port number (0-65535, **DEFAULT**: 13717)                                                           |
| `-if, --interface-name <name>`   | Specify the network interface name. (**DEFAULT**: eth0)                                                     |
| Shutdown control parameters      |                                                                                                             |
| `-st, --shutdown-timeout <s>`    | Maximum time (seconds) to wait for a clean shutdown before considering failure. (**DEFAULT**: 600, -1: inf) |
| `-pd, --probe-delay <s>`         | Define the delay (seconds) between ARP (IPv4) and NS (IPv6) probes. (**DEFAULT**: 4)                        |
| Wake-up control parameters       |                                                                                                             |
| `-nb, --number-attempt <number>` | Set the number of Wake-On-LAN attempts. (**DEFAULT**: 3)                                                    |
| `-t, --time-between-attempt <s>` | Set the time in seconds between attempts. (**DEFAULT**: 30)                                                 |
| `-kc, --keep-client <0\|1>`      | Keep the client monitored if it doesn't start after <-nb> attempt(s). (0: NO, 1: Yes, **DEFAULT**: 1)       |
| `-help`                          | Display help message and examples.                                                                          |


Examples:
```bash
./wakupator -H 192.168.0.37 -p 12345 -if eth2 -nb 5 -t 15 -kc 1
./wakupator --host 2001:0db8:3c4d:c202:1::2222 --port 54321 --interface-name enp4s0 --number-attempt 6 --time-between-attempt 10 --keep-client 0
```

___

### Register a machine

To register a machine with Wakupator, establish a TCP connection to Wakupator and send a JSON payload.  
Wakupator will wait for the machine to shut down after responding with `OK.`.
Any other response indicates an error, and Wakupator will not proceed.  

Once the machine is offline, Wakupator will monitor and spoof all provided IPs/ports.

**Important:** The client must register itself shortly before shutting down.  
An example systemd service and a Python script for registration are available in `example/machine`.

### Examples JSON payload

Here are two examples of JSON payloads for registering a machine:

**Single monitored IPv4 address:**
`````json
{
    "mac": "be:ef:fa:ce:c0:de",
    "name": "MyMachineName",
    "monitor": [
        {
            "ip": "192.168.0.12",
            "port": [25565]
        }
    ]
}
`````

**Multiple monitored IPs (IPv4 and IPv6):**
`````json
{
    "mac": "be:ef:fa:ce:c0:de",
    "name": "MyMachineName",
    "monitor": [
        {
            "ip": "192.168.0.12",
            "port": [22, 25565]
        },
        {
          "ip": "2001:0db8:3c4d:c202:1::2222",
          "port": [25565, 1234]
        }
    ]
}
`````

>[!IMPORTANT]
> Make sure the MAC address matches the monitored machine and that the JSON is sent just before shutdown.

___

## Example

### Context

In this example, Wakupator runs on my Raspberry PI (`raspberrypi`). I have another machine (`tartiflette`) 
hosting services such as a Minecraft server bound to the IPv6 address (2001:0db8:3c4d:4d58:1::2222).

I don’t want this machine to run 24/7, wasting electricity most of the time.

My goal with Wakupator:

- Wake up the machine (`tartiflette`) when traffic is detected on:
  - IP `2001:0db8:3c4d:4d58:1::2222` on ports 25565 (Minecraft) or 22 (SSH).
  - IP `192.168.0.37` on port 22 (SSH).
- The machine may also be started manually, and Wakupator will detect it automatically.

### Launch Wakupator

First, we need to launch `Wakupator` on a machine. In this example, it runs on `raspberrypi`, and we will use the `release` version.

*Ensure that the port (default: 13717) is allowed in the host's firewall if necessary.*

Once Wakupator is running, you should see the following log:

```bash
journalctl -f -u wakupator
or
systemctl status wakupator
```

At this point, with Wakupator running, you should see this log:

```
Feb 06 19:20:01 raspberrypi wakupator[2773297]: [INFO] Ready to register clients!
```

### Prepare the JSON

Retrieve the MAC address of the network interface on `tartiflette` that will be monitored..

For this, you can use the command `ip link`:

```bash
    nathanj@tartiflette:~$ ip link
    [...]
    2: enp4s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether d8:cb:8a:39:be:a1 brd ff:ff:ff:ff:ff:ff
    # here ->  ^^^^^^^^^^^^^^^^^
```

Now, for each IP and its associated port(s) of the services you want to monitor, construct a JSON object as follows:

Here's how my JSON looks:

`````json
{
    "mac": "d8:cb:8a:39:be:a1",
    "name": "Tartiflette",
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

### Automate machine registration during shutdown process

Create a simple Python script to send this JSON payload.  
Place the script in `/etc/wakupator/register_to_wakupator.py`.

Create a systemd service on `tartiflette` to execute this Python script just before shutdown.  
Place the service file in `/etc/systemd/system/register.service`.

All related files are in `example/machine/`.

Then execute these commands to enable the service: 
```bash
systemctl daemon-reload
systemctl enable register.service

#Verify the status
systemctl status register
 register.service - Register the system to Wakupator
     Loaded: loaded (/etc/systemd/system/register.service; enabled; preset: enabled)
     Active: inactive (dead) # <-- It is normal that the service is inactive at this point, as it will run only during shutdown.
```

To resume, when the machine shuts down, a Python script that sends the JSON payload to Wakupator is automatically executed by the service.

### Register the machine

To register the machine, shut it down manually or using /sbin/shutdown now.

Ideally, create a custom shutdown script that executes the registration under certain conditions, e.g., when there is no network activity.
But for this test, we're going to shut down the machine manually.

After shutting down the machine, you should see a log similar to this on the host, `raspberrypi`:

```
Feb 06 19:22:38 raspberrypi wakupator[2773297]: [INFO] New client registered: Tartiflette (d8:cb:8a:39:be:a1)
                                                              - IP: 2001:0db8:3c4d:4d58:1::2222, port: [25565, 22]
                                                              - IP: 192.168.0.37, port: [22]
Feb 06 19:22:38 raspberrypi wakupator[2773297]: [INFO] Client Tartiflette (D8:CB:8A:39:be:a1): Waiting for the machine to stop completely before proceeding with the monitoring...
Feb 06 19:22:38 raspberrypi wakupator[2773297]: [INFO] Client Tartiflette (D8:CB:8A:39:be:a1): Using the IP 2001:0db8:3c4d:4d58:1::2222 as representative to check if the machine is off.
Feb 06 19:22:42 raspberrypi wakupator[2773297]: [INFO] Client Tartiflette (D8:CB:8A:39:be:a1): ICMPv6 NS Request sent to 2001:0db8:3c4d:4d58:1::2222. (#1)
Feb 06 19:22:46 raspberrypi wakupator[2773297]: [INFO] Client Tartiflette (D8:CB:8A:39:be:a1): The machine seems to be off in approximately 8s.
Feb 06 19:22:46 raspberrypi wakupator[2773297]: [INFO] Client Tartiflette (D8:CB:8A:39:be:a1): Start spoofing and monitoring IP addresses.
```

### Final test

Now, test Wakupator's behavior by triggering one of your rules. I'll test it by initiating a TCP connection to IP 
`192.168.0.37` on port 22 (SSH).

You can also use `netcat` to simulate a TCP connection on a specific port:

````bash
nc -zv 192.168.0.37 22
````

The machine should start up immediately, and Wakupator is logging every attempt and the boot time of the machine:

````
Feb 06 19:24:18 raspberrypi wakupator[2773297]: [INFO] Client Tartiflette (D8:CB:8A:39:be:a1): traffic detected.
Feb 06 19:24:18 raspberrypi wakupator[2773297]: [INFO] Client Tartiflette (D8:CB:8A:39:be:a1): Packet Info: From 192.168.0.148:57794 to 192.168.0.37:22.
Feb 06 19:24:18 raspberrypi wakupator[2773297]: [INFO] Client Tartiflette (D8:CB:8A:39:be:a1): Wake-On-Lan sent. (#1)
Feb 06 19:24:37 raspberrypi wakupator[2773297]: [INFO] Client Tartiflette (D8:CB:8A:39:be:a1): the machine has been started successfully. (20s)
Feb 06 19:24:37 raspberrypi wakupator[2773297]: [INFO] Client Tartiflette (D8:CB:8A:39:be:a1): Has been removed from monitoring. Total monitoring duration: 2m 13s
````

You can also start the machine manually (by pressing the power button, or with a manual WoL packet), and Wakupator will see it, 
and log this message:

````
Feb 06 19:30:45 raspberrypi wakupator[2773297]: [INFO] Client Tartiflette (D8:CB:8A:39:be:a1): the machine has been started manually.
Feb 06 19:30:45 raspberrypi wakupator[2773297]: [INFO] Client Tartiflette (D8:CB:8A:39:be:a1): Has been removed from monitoring. Total monitoring duration: 51s
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