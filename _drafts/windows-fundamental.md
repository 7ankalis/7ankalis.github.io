---
layout: post
title: Windows Fundamentals 
description: Some basics about the Windows OS.
category: 
tags: windows mmc ntfs filesystem wmi
image: 
---


# Core aspects
To know which Windows version wwe're working with, we can use the `WMI` functionality. 
`WMI` is a wrapper around the OS' `SWbemServices` object which provides and facilitates interactions with some OS components: hardware, network configs..etc 

```powershell
Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber
```
The `Get-WmiObject` cmdlet can give us various information. The `ComputerName` parameter can give us information about remote computers.

It can also be used to start and stop services on local/remote computers.

In the command above we used `win32_OperatingSystem` class. Some other useful classes are:
1. win32_process: Get a process listing.
2. win32_service: Get a services listing.
3. win32_bios: Get BIOS information.(BIOS stands for Basic Input/Output System)

