#!/usr/bin/expect -f

set delKnownHosts "del_known_hosts.sh"
set dataLoggerServer "192.168.1.99"
set username "root"
set password "qsefthuk"

set timeout 30

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$dataLoggerServer
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# update time
expect "*:~# "
send "apt -y install ntp\r"
expect "*:~# "
send "apt -y install ntpdate\r"
expect "*:~# "
send "sudo ntpdate ntp.ubuntu.com\r"

expect "*:~# "
send "exit\r"

