#!/usr/bin/expect -f

set delKnownHosts "del_known_hosts.sh"
set ip "192.168.1.99"
set username "dataloggerserver"
set password "qsefthuk"
set collectuser "testbed_2"
set collect_ip "192.168.1.110"
set collect_password "qsefthuk"

set timeout 15

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

expect "*:~$ "
send "rm ~/.ssh/known_hosts\r"

expect "*:~$ "
send "scp -r $collectuser@$collect_ip:/home/Public/data /home/$username/Desktop/All_data/ \r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$collect_password\r"
expect "*:~$ "
send "exit\r"


