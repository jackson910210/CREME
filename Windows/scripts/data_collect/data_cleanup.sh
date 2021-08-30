#!/usr/bin/expect -f

set delKnownHosts "del_known_hosts.sh"
set ip "192.168.1.110"
set username "testbed_2"
set password "qsefthuk"

set timeout 15

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*>"
send "del C:\\Users\\Public\\data\r"
expect " (Y/N)?"
send "Y\r"
expect "*>"
send "del C:\\Users\\Public\\Sec_log.evtx\r"
expect "*>"
send "del C:\\Users\\Public\\Sys_log.evtx\r"
expect "*>"
send "exit\r"


