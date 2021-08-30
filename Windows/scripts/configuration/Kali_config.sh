#!/usr/bin/expect -f

set delKnownHosts "del_known_hosts.sh"
set kali_ip "192.168.1.106"
set username "root"
set password "qsefthuk"
set path "/root/Desktop"
set controller_user "controller"
set controller_ip "192.168.1.4"
set controller_path "/home/controller/Desktop/scripts/configuration/config_kali"
set controller_pass "qsefthuk"

set timeout 30

# SSH connection
spawn /bin/bash $delKnownHosts
send "exit\r"

spawn ssh $username@$kali_ip
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

# update time
expect "#"
send "apt -y install ntp\r"
expect "#"
send "apt -y install ntpdate\r"
expect "#"
send "sudo ntpdate ntp.ubuntu.com\r"

#config dns
expect "#"
send "rm ~/.ssh/known_hosts\r"
expect "#"
send "scp -r $controller_user@$controller_ip:$controller_path $path\r"
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$controller_pass\r"

expect "#"
send "chmod +x $path/*.py \r"

expect "#"
send "exit\r"

