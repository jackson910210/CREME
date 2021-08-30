#!/usr/bin/expect -f

set delKnownHosts "del_known_hosts.sh"
set kali_ip "192.168.1.106"
set username "root"
set password "qsefthuk"
set path "/root/Desktop"
set prepared_file "config_kali/cred_steal.py"

set timeout 15

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$kali_ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"


expect "#"
send "python3 $path/$prepared_file\r"

sleep 110

expect "#"
send "exit\r"


