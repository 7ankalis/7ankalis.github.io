---
layout: post
title: thm-wonderland
description: TryHackMe Medium Machine 
category:
tags:
---

## Wonderland

>Overall it was a fun box. Pretty basic enumeration and exploitation techniques we just have to keep up with the a bit long attack vector. Before diving into the walk-through here's a summary of some of the techniques we'll cover shortly:
>>1. The enumeration didn't have anything complicated: <mark style="color:blue;">basic nmap scan, few fuzzing</mark> and we find some <mark style="color:blue;">cleartext credentials</mark> that'll ssh us into the machine as a regular user. The user flag was in a very strange directory (as the comments stated as well)
>>2. To get to root, we'll be doing some <mark style="color:blue;">lateral movement</mark> as well. from the foothold as Alice we'll exploit a basic <mark style="color:blue;">Module Shadowing</mark> to gain access to rabbit.
>>3. From there, we'll find a binary with a <mark style="color:blue;">SUID bit</mark> that we'll use to gain access to hatter account through a <mark style="color:blue;">PATH Hijacking</mark>.
>> 4. Finally, for root, back to the basics after some manual inspection, linpeas.sh (after <mark style="color:blue;">File transferring</mark> it to the target) shows <mark style="color:blue;">CAP\_SETUID</mark> available for the Perl interpreter!

>> Pwned successfully!
{: .prompt:tip}
> [!WARNING]
