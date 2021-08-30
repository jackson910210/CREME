#!/usr/bin/expect -f
set delKnownHosts "del_known_hosts.sh"
set ip "192.168.1.106"
set username "root"
set password "qsefthuk"
#set path [lindex $argv 4]
#set pids_file [lindex $argv 5]

set timeout 15

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"
spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# Pymetasploit (Py3)
expect "*:~#"
send "msfrpcd -P kali -S \r"

#expect "*:~# "
#send "ps -ef | grep 'msfrpcd' | awk '{print \$2}' > $path/$pids_file\r"

expect "*:~#"
send "exit\r"




