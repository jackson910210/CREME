import os
import time


# Config clients

os.system("/home/controller/Desktop/scripts/configuration/client_config_base.sh")
time.sleep(60)
os.system("/home/controller/Desktop/scripts/configuration/dataloggerserver_config.sh")
time.sleep(60)
os.system("/home/controller/Desktop/scripts/configuration/kali_config.sh")
time.sleep(60)
print("config complete")
# Start data collecting
os.system("/home/controller/Desktop/scripts/data_collect/stat_collect.sh")
time.sleep(30)
os.system("/home/controller/Desktop/scripts/data_collect/traffic_collect.sh")

time.sleep(30)
print("data collecting start")
# Start attack
os.system("/home/controller/Desktop/scripts/attack/start_metasploit.sh")
time.sleep(30)
os.system("/home/controller/Desktop/scripts/attack/start_attack_cred_steal.sh")
time.sleep(120)
#os.system("/home/controller/Desktop/scripts/attack/start_attack_disk_wipe.sh")
os.system("/home/controller/Desktop/scripts/attack/cleanup_windows.sh")

time.sleep(30)
print("attack complete")
# Stop collecting data
os.system("/home/controller/Desktop/scripts/data_collect/stat_stop.sh")
time.sleep(30)
os.system("/home/controller/Desktop/scripts/data_collect/traffic_stop.sh")
time.sleep(30)
os.system("/home/controller/Desktop/scripts/data_collect/log_stop.sh")
time.sleep(30)
print("data collecting stop")
# Send data to dataloggerserver
os.system("/home/controller/Desktop/scripts/data_collect/collect_all.sh")
time.sleep(60)
os.system("/home/controller/Desktop/scripts/data_collect/data_cleanup.sh")
print("data sent to dataloggerserver")
#
