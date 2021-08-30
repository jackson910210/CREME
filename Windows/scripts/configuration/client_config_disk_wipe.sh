#!/usr/bin/expect -f

set delKnownHosts "del_known_hosts.sh"
set ip "192.168.1.110"
set username "testbed_2"
set password "qsefthuk"

set timeout 15

spawn /bin/bash $delKnownHosts
send "exit\r"

spawn scp -r /home/controller/Desktop/scripts/configuration/config $username@$ip:/home/$username/Desktop/
expect "*continue connecting (yes/no*)? "
send "yes\r"
expect " password: "
send "$password\r"

sleep 15

spawn ssh $username@$ip
expect " password: "
send "$password\r"

expect "*>"
send "net start w32time\r"
expect "*>"
send "w32tm /resync /force\r"
expect "*>"
send "cd Desktop\r"
expect "*>"
send "cd config\r"
expect "*>"
send "Wireshark-win64-3.4.0.exe /S\r"
expect "*>"
send "winpcap-nmap-4.13.exe /S\r"
expect "*>"
send "cd ..\r"
expect "*>"
send "cd ..\r"
expect "*:~#"
send "cd ..\r"
expect "*>"
send "cd Public\r"
expect "*>"
send "mkdir data\r"
expect "*>"
send {copy "C:\Users\Public\Music\Sample Music\Kalimba.mp3" "C:\Users\Public\" }
send \r
expect "*>"
send "exit\r"


