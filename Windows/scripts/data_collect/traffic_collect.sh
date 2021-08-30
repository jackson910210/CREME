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
send "cd ..\r"
expect "*>"
send "cd ..\r"
expect "*>"
send "cd ..\r"
expect "*>"
send "cd wireshark\r"
expect "*>"
send "dumpcap.exe -i 1 -P -w C:\\Users\\Public\\data\\traffic.pcap\r"
expect "*>"
send "exit\r"


