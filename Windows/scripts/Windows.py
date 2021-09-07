import os

class Creme:
    disk_wipe = True
    data_theft = True
    models_name = ["decision_tree", "naive_bayes", "extra_tree", "knn", "random_forest", "XGBoost"]

    # should update to allow users define weights on the website
    weights = {"attack_types": 4 / 10 / 20, "attack_scenarios": 2 / 10 / 20, "data_sources": 1 / 10 / 6,
               "labeled_data": 1 / 10 / 6, "feature_set": 1 / 10 / 6, "metadata": 1 / 10}

    def __init__(self, dls, target_server, benign_server, vulnerable_clients, non_vulnerable_clients,
                 attacker_server, malicious_client, disk_wipe, data_theft):
        # self.stage = 0
        # self.status = 1
        # self.finishedTasks = []
        # self.messages = []
        # self.sizes = []
        # self.finishedStageList = []
        # Helper.clearProgressData()

        # Machines
        self.dls = dls
        self.target_server = target_server
        self.benign_server = benign_server
        self.vulnerable_clients = vulnerable_clients
        self.non_vulnerable_clients = non_vulnerable_clients
        self.attacker_server = attacker_server
        self.malicious_client = malicious_client

        # Attack scenarios. True/False

        Creme.disk_wipe = disk_wipe
        Creme.data_theft = data_theft


    def configure(self):
        #stage = 1
        #ProgressHelper.update_stage(stage, f"Controller is configuring {self.dls.hostname}", 5, new_stage=True)
        self.dls.configure()
        #ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {self.dls.hostname}", 5,
        #                            finished_task=True, override_pre_message=True)

        for vulnerable_client in self.vulnerable_clients:
            #ProgressHelper.update_stage(stage, f"Controller is configuring {vulnerable_client.hostname}", 5)
            vulnerable_client.configure()
            #ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {vulnerable_client.hostname}", 5,
            #                            finished_task=True, override_pre_message=True)

        for non_vulnerable_client in self.non_vulnerable_clients:
            #ProgressHelper.update_stage(stage, f"Controller is configuring {non_vulnerable_client.hostname}", 5)
            non_vulnerable_client.configure()
            #ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {non_vulnerable_client.hostname}", 5,
            #                            finished_task=True, override_pre_message=True)
        #ProgressHelper.update_stage(stage, f"Controller is configuring {self.attacker_server.hostname}", 5)
        self.attacker_server.configure()
        #ProgressHelper.update_stage(stage, f"Controller FINISHED configuring {self.attacker_server.hostname}", 5,
        #                            finished_task=True, override_pre_message=True)
    def start_collect_data(self):
        for vulnerable_client in self.vulnerable_clients:
            vulnerable_client.start_collect_data()
        for non_vulnerable_client in self.non_vulnerable_clients:
            non_vulnerable_client.start_collect_data()

# Classes for machines

class Machine:
    show_cmd = False  # a flag use to show cmd or execute cmd

    # Controller's information
    controller_hostname = None
    controller_ip = None
    controller_username = None
    controller_password = None
    controller_path = None

    def __init__(self, hostname, ip, username, password, path):
        self.hostname = hostname
        self.ip = ip
        self.username = username
        self.password = password
        self.path = path

    def __str__(self):
        attrs = vars(self)
        return ', '.join("%s: %s" % item for item in attrs.items())

class DataLoggerServer(Machine, implements(IConfiguration), implements(IConfigurationCommon),
                       implements(IDataCollection), implements(IDataCentralization)):
    """

    """
    def __init__(self, hostname, ip, username, password, path, network_interface, tcp_file="traffic.pcap",
                 tcp_pids_file="tcp_pids.txt", atop_interval=1, time_window_traffic=1):
        super().__init__(hostname, ip, username, password, path)
        self.path = path
        self.network_interface = network_interface
        self.tcp_file = tcp_file
        self.tcp_pids_file = tcp_pids_file
        self.atop_interval = atop_interval
        self.time_window_traffic = time_window_traffic

    def configure(self):
        self.configure_base()

    def configure_base(self):
        filename_path = "configuration/./dataloggerserver_base.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # dataloggerserver ip: 192.168.1.99, username: root, password: qsefthuk


    '''
    def download_time_file(self, data_logger_client, time_file):
        filename_path = "data_collection/./download_atop_data.sh"
        parameters = [self.ip, self.username, self.password, data_logger_client.ip, data_logger_client.username,
                      data_logger_client.password, data_logger_client.path, time_file, self.path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def centralize_data(self, data_logger_client, contain_continuum_log=False):
        self.download_atop_data(data_logger_client)
        if contain_continuum_log:  # download apache continuum's log
            remote_path = '/opt/apache_continuum/apache-continuum-1.4.2/logs'
            remote_log = 'continuum.log'
            new_log = '{0}_continuum.log'.format(data_logger_client.hostname)
            self.download_log_data(data_logger_client, remote_path, remote_log, new_log)

    def centralize_time_files(self, data_logger_client, time_files):
        for time_file in time_files:
            self.download_time_file(data_logger_client, time_file)
    '''

class VulnerableClient(DataLoggerClient, implements(IConfiguration), implements(IConfigurationCommon),
                       implements(IConfigurationAttack), implements(IConfigurationBenign), implements(IDataCollection),
                       implements(IBenignReproduction), implements(ICleaningBenignReproduction)):
    def __init__(self, hostname, ip, username, password, path, server=None, ftp_folder="ftp_folder", sleep_second='2',
                 benign_pids_file="benign_pids.txt"):
        super().__init__(hostname, ip, username, password, path)
        self.server = server  # target server
        self.ftp_folder = ftp_folder
        last_ip = int(ip.split('.')[-1])
        self.virtual_account = "client{0}".format(str(last_ip))
        self.target_virtual_account = "client{0}".format(str(last_ip + 1))
        self.sleep_second = sleep_second
        self.benign_pids_file = benign_pids_file

    def configure(self):
        self.configure_base()
        if Creme.disk_wipe:
            self.configure_disk_wipe()
        if Creme.data_theft:
            self.configure_data_theft()

    def configure_base(self):
        filename_path = "configuration/./client_config_base.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # vul username: testbed_2, password: qsefthuk, ip: 192.168.1.110

    '''
    def configure_benign_services(self):
        filename_path = "configuration/./Client_benign_services.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.ftp_folder,
                      self.controller_ip, self.controller_username, self.controller_password, self.controller_path,
                      self.server.ip, self.virtual_account, self.server.domain_name]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
    '''

    def start_collect_data(self):
        self.start_collect_data_stat()
        self.start_collect_data_traffic()

    def start_collect_data_stat(self):
        filename_path = "data_collect/./stat_collect.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def start_collect_data_traffic(self):
        filename_path = "data_collect/./traffic_collect.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data(self):
        self.stop_collect_data_stat()
        self.stop_collect_data_traffic()
        self.stop_collect_data_log()

    def stop_collect_data_stat(self):
        filename_path = "data_collect/./stat_stop.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data_traffic(self):
        filename_path = "data_collect/./traffic_stop.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data_log(self):
        filename_path = "data_collect/./log_stop.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def send_data(self):
        filename_path = "data_collect/./collect_all.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_disk_wipe(self):
        filename_path = "configuration/./client_config_disk_wipe.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_data_theft(self):
        pass

   '''
    def start_benign_behaviors(self):
        filename_path = "configuration/./Client_start_benign_behaviors.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.ftp_folder,
                      self.target_virtual_account, self.sleep_second, self.benign_pids_file, self.server.domain_name]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_benign_behaviors(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.benign_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def clean_benign_reproduction(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.benign_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
    '''

class NonVulnerableClient(DataLoggerClient, implements(IConfiguration), implements(IConfigurationCommon),
                          implements(IConfigurationBenign), implements(IDataCollection),
                          implements(IBenignReproduction), implements(ICleaningBenignReproduction)):
    def __init__(self, hostname, ip, username, password, path, server=None, ftp_folder="ftp_folder", sleep_second='2',
                 benign_pids_file="benign_pids.txt"):
        super().__init__(hostname, ip, username, password, path)
        self.server = server  # benign server
        self.ftp_folder = ftp_folder
        last_ip = int(ip.split('.')[-1])
        self.virtual_account = "client{0}".format(str(last_ip))
        self.target_virtual_account = "client{0}".format(str(last_ip + 1))
        self.sleep_second = sleep_second
        self.benign_pids_file = benign_pids_file
        # something else

    def configure(self):
        self.configure_base()
        self.configure_data_collection()
        #self.configure_benign_services()

    def configure_base(self):
        filename_path = "configuration/./client_config_base.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        # vul username: non_vul, password: qsefthuk, ip: 192.168.1.
    '''
    def configure_benign_services(self):
        filename_path = "configuration/./Client_benign_services.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.ftp_folder,
                      self.controller_ip, self.controller_username, self.controller_password, self.controller_path,
                      self.server.ip, self.virtual_account, self.server.domain_name]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
    '''

    def start_collect_data(self):
        self.start_collect_data_stat()
        self.start_collect_data_traffic()

    def start_collect_data_stat(self):
        filename_path = "data_collect/./stat_collect.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def start_collect_data_traffic(self):
        filename_path = "data_collect/./traffic_collect.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data(self):
        self.stop_collect_data_stat()
        self.stop_collect_data_traffic()
        self.stop_collect_data_log()

    def stop_collect_data_stat(self):
        filename_path = "data_collect/./stat_stop.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data_traffic(self):
        filename_path = "data_collect/./traffic_stop.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_collect_data_log(self):
        filename_path = "data_collect/./log_stop.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def send_data(self):
        filename_path = "data_collect/./collect_all.sh"
        parameters = [self.ip, self.username, self.password]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
    '''
    def start_benign_behaviors(self):
        filename_path = "configuration/./Client_start_benign_behaviors.sh"
        parameters = [self.hostname, self.ip, self.username, self.password, self.path, self.ftp_folder,
                      self.target_virtual_account, self.sleep_second, self.benign_pids_file, self.server.domain_name]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_benign_behaviors(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.benign_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def clean_benign_reproduction(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.benign_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
    '''
class AttackerServer(Machine, implements(IConfiguration), implements(IConfigurationCommon),
                     implements(IConfigurationAttack), implements(IMiraiAttackerServer),
                     implements(ICleaningAttackReproduction), implements(IConfigurationAttackerSide),
                     implements(IDiskWipeAttackerServer), implements(IRansomwareAttackerServer),
                     implements(IResourceHijackingAttackerServer), implements(IEndPointDosAttackerServer),
                     implements(IDataTheftAttackerServer), implements(IRootkitRansomwareAttackerServer)):
    data_logger_server_ip = None
    DNS_server_ip = None
    mirai_o4_xxx_1 = None
    mirai_o4_xxx_2 = None

    def __init__(self, hostname, ip, username, password, path="/home/client1/Desktop/reinstall",
                 cnc_pids_file="cnc_pids.txt", transfer_pids_file="transfer_pids.txt", number_of_new_bots="3",
                 targeted_attack="", DDoS_type="udp", DDoS_duration="30"):
        super().__init__(hostname, ip, username, password, path)
        self.cnc_pids_file = cnc_pids_file
        self.transfer_pids_file = transfer_pids_file
        self.bot_input_files = []
        self.num_of_new_bots = number_of_new_bots
        self.targeted_attack = targeted_attack
        self.DDoS_type = DDoS_type
        self.DDoS_duration = DDoS_duration
        self.killed_pids_file = "killed_pids.txt"
        # self.flag_finish = "Creme_finish_attack_scenario"

    def configure(self):
        self.configure_base()

        #if Creme.disk_wipe or Creme.data_theft:
        #    self.configure_pymetasploit()
        if Creme.disk_wipe:
            self.configure_disk_wipe()
        if Creme.data_theft:
            self.configure_data_theft()


    def configure_base(self):
        filename_path = "configuration/./Kali_config.sh"
        parameters = [self.ip, self.username, self.password, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
        '''
        set delKnownHosts "del_known_hosts.sh"
        set kali_ip "192.168.1.106"
        set username "root"
        set password "qsefthuk"
        set controller_user "controller"
        set controller_ip "192.168.1.4"
        set controller_path "/home/controller/Desktop/scripts/configuration/config_kali"
        set controller_pass "qsefthuk"
        '''
    '''
    def configure_pymetasploit(self):
        filename_path = "configuration/./AttackerServer_pymetasploit.sh"
        parameters = [self.ip, self.username, self.password, self.path]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)
    '''
    def configure_disk_wipe(self):
        prepared_files = "CREME/CREME_backend_execution/scripts/configuration/prepared_files/disk_wipe/attacker_server"
        filename_path = "configuration/./AttackerServer_disk_wipe.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, prepared_files]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def configure_data_theft(self):
        prepared_files = "CREME/CREME_backend_execution/scripts/configuration/prepared_files/data_theft/attacker_server"
        filename_path = "configuration/./AttackerServer_data_theft.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.controller_ip, self.controller_username,
                      self.controller_password, self.controller_path, prepared_files]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def disk_wipe_start_metasploit(self):
        filename_path = "attacks/disk_wipe/./AttackerServer_start_metasploit.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def disk_wipe_first_stage(self):
        filename_path = "attacks/disk_wipe/./AttackerServer_first_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def disk_wipe_second_stage(self):
        filename_path = "attacks/disk_wipe/./AttackerServer_second_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def disk_wipe_third_stage(self):
        filename_path = "attacks/disk_wipe/./AttackerServer_third_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def data_theft_start_metasploit(self):
        filename_path = "attacks/data_theft/./AttackerServer_start_metasploit.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def data_theft_first_stage(self):
        filename_path = "attacks/data_theft/./AttackerServer_first_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def data_theft_second_stage(self):
        filename_path = "attacks/data_theft/./AttackerServer_second_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def data_theft_third_stage(self):
        filename_path = "attacks/data_theft/./AttackerServer_third_stage.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.targeted_attack]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def stop_metasploit(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

    def clean_disk_wipe(self):
        self.stop_metasploit()
        self.clean_windows()

    def clean_data_theft(self):
        self.stop_metasploit()
        self.clean_windows()

    def clean_windows(self):
        filename_path = "./kill_pids.sh"
        parameters = [self.ip, self.username, self.password, self.path, self.killed_pids_file]
        ScriptHelper.execute_script(filename_path, parameters, self.show_cmd)

# Helper
class ScriptHelper:
    @staticmethod
    def get_del_known_hosts_path(scripts_path, del_script="./del_known_hosts.sh"):
        del_known_hosts_path = os.path.join(scripts_path, del_script)
        return del_known_hosts_path

    @staticmethod
    def get_script_cmd(file):
        scripts_path = os.path.join("CREME_backend_execution", "scripts")
        cmd = os.path.join(scripts_path, file)
        del_known_hosts_path = ScriptHelper.get_del_known_hosts_path(scripts_path, "./del_known_hosts.sh")
        return cmd, del_known_hosts_path

    @staticmethod
    def execute_script(filename_path, parameters, show_cmd=False):
        cmd, del_known_hosts_path = ScriptHelper.get_script_cmd(filename_path)
        cmd += " {0}".format(del_known_hosts_path)
        for parameter in parameters:
            cmd += " {0}".format(parameter)
        print(cmd) if show_cmd else os.system(cmd)




