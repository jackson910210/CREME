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
send "taskkill /IM virus_test.exe /F\r"
expect "*>"
send "SC DELETE virus_test\r"
expect "*>"
send "del C:\\Windows\\Temp\\virus_test.exe\r"
expect "*>"
send "exit\r"


