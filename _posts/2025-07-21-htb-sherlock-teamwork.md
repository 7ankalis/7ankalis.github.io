---
layout: post
title: HackTheBox Sherlock : Teamwork
description: Threat Intelligence Investigation
image: assets/htb-sherlock-1.png
category: Blue Team
tags: blueteam threat-intel sherlock hackthebox mitre supply-chain-attack
date: 2025-07-21 20:03 +0100
---
# Teamwork
## Scenario and handout
>It is Friday afternoon and the SOC at Edny Consulting Ltd has received alerts from the workstation of Jason Longfield, a software engineer on the development team, regarding the execution of some discovery commands. Jason has just gone on holiday and is not available by phone. The workstation appears to have been switched off, so the only evidence we have at the moment is an export of his mailbox containing today's messages. As the company was recently the victim of a supply chain attack, this case is being taken seriously and the Cyber Threat Intelligence team is being called in to determine the severity of the threat.

And given a zip file containing the following content:
```bash
$ ll jasonlongfield@edny.net/
total 764
./
../
49K Building Systems Exposed 🏢, Cellebrite blocks Serbia 📱, Cracking Dashcams 📷.eml'
A reference manual for people who design and build software.eml'
GibberLink Breakthrough in How Voice Assistants Communicate AI-to-AI.eml'
GPT 4.5 4️ ⃣, Meta AI Chatbot App 📱, Emergent Misalignment ⚖️ .eml'
HashiCorp joins IBM 🤝, Custom Transport Protocol ✨, Copilot for Azure DevOps 🔮.eml'
Microsoft will pull the plug on Skype in May.eml'
OpenAI launches GPT-4.5 🧠, Figure home robots 🤖, advice for CS students 👨‍💻.eml'
Opportunity to Invest in NFT Game Project.eml'
SEC Drops Consensys Case ⚖️ , Base Upgrades 🦾, Metamask’s Updates 🦊.eml'
SWLW #640 The burdens of data, Creating a sense of stability, and more.eml'
Update on JavaScript Authentication Module.eml'
Your New Online Project Management Tool Smartsheet.eml'
Your online event invitation for "Sync before Jason holiday Software Development Progress and Insights".eml'
```

***

## Analysis

So, there are many things that took my attention, especially the the "online invitations" but they lead to nothing and they seemed legitimate. Next, that good looking "Opportunity to Invest in NFS" one. It surely is tempting and pretty attractive to someone with that interest in NFT.
And surely enough:
```
From : Theodore Todtenhaupt <theodore.todtenhaupt@developingdreams.site>
To   : jasonlongfield@edny.net
Sent time:	28 Feb, 2025 3:35:40 PM

Dear Jason,

I hope this message finds you well.
I am following up on our quick chat on X to discuss an exciting investment opportunity in an NFT game project that is nearing completion. As an investor in the project, I have been impressed by the progress and potential of this venture. However, we are seeking additional investment to take the project to the next level.
The DevelopingDreams is currently in the process of developing a new play-to-earn (P2E) game.
We finished beta version of this game but need expert game developers because of issues and new version.
Would you be interested in learning more about this opportunity? I would be happy to provide you with more details and discuss how you can become a part of this innovative project.

Here you can find the beta version of the game for testing (use password DTWBETA2025). 

Best regards,

Theodore Todtenhaupt
DevelopingDreams, CEO
Craven Road 7
London, W2 3BP
https://developingdreams.site

```
A broken website, a link to an inexisting asset, maybe to the same domain mentionned in the mail signature and a mention of personal interests not under the scope of the dev team of a company and the mail's domain is external. This is the one.
Let's query and see this domain and its registring information.
```bash
whois developingdreams.site
Domain Name: DEVELOPINGDREAMS.SITE
Registry Domain ID: D523243662-CNIC
Registrar WHOIS Server: whois.godaddy.com
Registrar URL: https://www.godaddy.com/
Updated Date: 2025-03-19T18:09:21.0Z
Creation Date: 2025-01-31T11:43:39.0Z
Registry Expiry Date: 2026-01-31T23:59:59.0Z
```
The thing I think is important to see here is the registration time. It was registred less than a month before sending the mail.
So this might be a part of the infrastructure of the threat actor.
So, this thing has a name, or better say a Mitre ATT&CK tactic: **Resource Development** and to be more specific with the technique in here: **Acquire Infrastructure.Domains** which maps to **T1583.001**

***

### Infrastructure 
So, it is time to search for that domain and dig more into the infrastrucutre. Going to the [waybackmachine](https://web.archive.org/web/20250204120033/https://developingdreams.site/) we get a hit and see the saved website with the `DeTankWar` game in "beta" release as the threat actor said in the phishing mail.
![waybackmachine](assets/htb-teamwork-2.png)
__Recovered website page__
![waybackmachine](assets/htb-teamwork-3.png)
__The lovely Team__
![waybackmachine](assets/htb-teamwork-4.png)
__The malicious file game__
And a suspended X account. Perfect. This maps to MITRE's subtechnique called **Establish Accounts.Social Media Accounts** T1585.001

![waybackmachine](assets/htb-teamwork-5.png)

__Suspended X account__


***

### Malware
So, unzipping the given archive with the password mentionned in mail, we get `beta_release_v.1.32.exe` A PE32+ executable (GUI) x86-64, for MS Windows, with a sha256 hash value of **56554117d96d12bd3504ebef2a8f28e790dd1fe583c33ad58ccbf614313ead8c**. The act of hosting themalware artifacts is in itself a tactic called **Stage Capabilities.Upload** malware which maps to **T1608.001**

So going into VirusTotal, we get a ton of information dating back to that same period the mail and the whole infrastructure was set.

And most importatly, this [link](https://www.microsoft.com/en-us/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/) referencing Microsoft's analysis on a Norht Korean threat actor called Moonstone Sleet and how they trojanized PuTTY as a new weapon. This technique maps to MITRE's suppply chain compromise Technique which can be found [here](https://attack.mitre.org/techniques/T1195/) which was mentionned in the description as the company got hit by a supply chain attack. Specififcally **T1195.001**

Going a bit further for the other supply chain attacks in 2024, using Microsoft's and Kaspersky's threat reports, I found [this](https://securelist.com/ksb-story-of-the-year-2024/114883/) link to see all of the supply chain attacks per Kaspersky.
We found several attacks, of course. But the most relevant one was the JavaScript abuse since I know the pager attacks that happened earlier in 2024 (Free Palestine), the xz backdoor..etc.

Reading up more on this massive attacks in [here](https://censys.com/blog/july-2-polyfill-io-supply-chain-attack-digging-into-the-web-of-compromised-domains) leads to the answer: npm


Finally, this is the gem i found after some google dorking: <https://securitylabs.datadoghq.com/articles/stressed-pungsan-dprk-aligned-threat-actor-leverages-npm-for-initial-access/> 
This shows the full report of how everything about this supply chain attack worked.
the cherry on the top: T1218.011 to finish things off and evade defenses using a legitimate signed windows binary `rundll32.exe`
