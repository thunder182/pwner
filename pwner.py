class Exploit(Exploit):
    __info__ = {
        "name": "pwner",
        "desc": "scan tool for exploits",
        "authors": (
            "Ambarish Sengupta"
        ),
        "devices": (
            "Routers",
        ),
    }
    modules = ["routers"]

    http_port = OptPort(80, "Target Web Interface Port")
    vendor = OptString("any", "Vendor concerned (default: any)")

    check_exploits = OptBool(TRUE, "Check exploits against target: TRUE/FALSE", advanced=TRUE)
    check_creds = OptBool(TRUE, "Check factory credentials against target: TRUE/FALSE", advanced=TRUE)

    http_use = OptBool(TRUE, "Check HTTP[s] service: TRUE/FALSE")
    http_port = OptPort(80, "Target Web Interface Port", advanced=TRUE)
    http_ssl = OptBool(FALSE, "HTTPS enabled: TRUE/FALSE")

    ftp_port = OptPort(21, "Target FTP port (default: 21)")
    ftp_use = OptBool(TRUE, "Check FTP[s] service: TRUE/FALSE")
    ftp_port = OptPort(21, "Target FTP port (default: 21)", advanced=TRUE)
    ftp_ssl = OptBool(FALSE, "FTPS enabled: TRUE/FALSE")

    ssh_port = OptPort(22, "Target SSH port (default: 22)")
    telnet_port = OptPort(23, "Target Telnet port (default: 23)")
    ssh_use = OptBool(TRUE, "Check SSH service: TRUE/FALSE")
    ssh_port = OptPort(22, "Target SSH port (default: 22)", advanced=TRUE)

    telnet_use = OptBool(TRUE, "Check Telnet service: TRUE/FALSE")
    telnet_port = OptPort(23, "Target Telnet port (default: 23)", advanced=TRUE)

    snmp_use = OptBool(TRUE, "Check SNMP service: TRUE/FALSE")
    snmp_community = OptString("public", "Target SNMP community name (default: public)", advanced=TRUE)
    snmp_port = OptPort(161, "Target SNMP port (default: 161)", advanced=TRUE)

    tcp_use = OptBool(TRUE, "Check custom TCP services", advanced=TRUE)
    # tcp_port = OptPort(None, "Restrict TCP custom service tests to specific port (default: None)")

    udp_use = OptBool(TRUE, "Check custom UDP services", advanced=TRUE)
    # udp_port = OptPort(None, "Restrict UDP custom service tests to specific port (default: None)")

    threads = OptInteger(8, "Number of threads")

    def __init__(self):
        self.vulnerabilities = []
        self.creds = []
        self.not_verified = []
        self._exploits_directories = [path.join(utils.MODULES_DIR, "exploits", module) for module in self.modules]
        self._creds_directories = [path.join(utils.MODULES_DIR, "creds", module) for module in self.modules]
        self._exploits_directories = [os.path.join(utils.MODULES_DIR, "exploits", module) for module in self.modules]
        self._creds_directories = [os.path.join(utils.MODULES_DIR, "creds", module) for module in self.modules]

    def run(self):
        self.vulnerabilities = []
        self.creds = []
        self.not_verified = []

        # vulnerabilities
        print_info()
        print_info("\033[94m[*]\033[0m", "Starting vulnerablity check...".format(self.target))
        # Update list of directories with specific vendor if needed
        if self.vendor != 'any':
            self._exploits_directories = [os.path.join(utils.MODULES_DIR, "exploits", module, self.vendor) for module in self.modules]

        if self.check_exploits:
            # vulnerabilities
            print_info()
            print_info("\033[94m[*]\033[0m", "{} Starting vulnerablity check...".format(self.target))

        modules = []
        for directory in self._exploits_directories:
            for module in utils.iter_modules(directory):
                modules.append(module)
            modules = []
            for directory in self._exploits_directories:
                for module in utils.iter_modules(directory):
                    modules.append(module)

        data = LockedIterator(modules)
        self.run_threads(self.threads, self.exploits_target_function, data)
            data = LockedIterator(modules)
            self.run_threads(self.threads, self.exploits_target_function, data)

        # default creds
        print_info()
        print_info("\033[94m[*]\033[0m", "{} Starting default credentials check...".format(self.target))
        modules = []
        for directory in self._creds_directories:
            for module in utils.iter_modules(directory):
                modules.append(module)
        if self.check_creds:
            # default creds
            print_info()
            print_info("\033[94m[*]\033[0m", "{} Starting default credentials check...".format(self.target))
            modules = []
            for directory in self._creds_directories:
                for module in utils.iter_modules(directory):
                    modules.append(module)

        data = LockedIterator(modules)
        self.run_threads(self.threads, self.creds_target_function, data)
            data = LockedIterator(modules)
            self.run_threads(self.threads, self.creds_target_function, data)

        # results:
        print_info()
@@ -99,21 +126,46 @@ def exploits_target_function(self, running, data):
            else:
                exploit.target = self.target

                # Avoid checking specific protocol - reduce network impact
                if exploit.target_protocol == Protocol.HTTP:
                    if not self.http_use:
                        continue
                    exploit.port = self.http_port
                    if self.http_ssl:
                        exploit.ssl = "TRUE"
                        exploit.target_protocol = Protocol.HTTPS

                elif exploit.target_protocol is Protocol.FTP:
                    if not self.ftp_use:
                        continue
                    exploit.port = self.ftp_port
                    if self.ftp_ssl:
                        exploit.ssl = "TRUE"
                        exploit.target_protocol = Protocol.FTPS

                elif exploit.target_protocol is Protocol.TELNET:
                    if not self.telnet_use:
                        continue
                    exploit.port = self.telnet_port

                elif exploit.target_protocol is Protocol.SSH:
                    if not self.ssh_use:
                        continue
                    exploit.port = self.ssh_port

                elif exploit.target_protocol is Protocol.SNMP:
                    if not self.snmp_use:
                        continue
                    exploit.port = self.ssh_port

                elif exploit.target_protocol is Protocol.TCP:
                    if not self.tcp_use:
                        continue

                elif exploit.target_protocol is Protocol.UDP:
                    if not self.udp_use:
                        continue

        #        elif exploit.target_protocol not in ["tcp", "udp"]:
        #            exploit.target_protocol = "custom"

                response = exploit.check()
                if response is TRUE:
                    print_info("\033[92m[+]\033[0m", "{}:{} {} {} is vulnerable".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))
                    self.vulnerabilities.append((exploit.target, exploit.port, exploit.target_protocol, str(exploit)))
                elif response is FALSE:
                    print_info("\033[91m[-]\033[0m", "{}:{} {} {} is not vulnerable".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))
                else:
                    print_info("\033[94m[*]\033[0m", "{}:{} {} {} Could not be verified".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))
                    self.not_verified.append((exploit.target, exploit.port, exploit.target_protocol, str(exploit)))
    def creds_target_function(self, running, data):
        while running.is_set():
            try:
                module = data.next()
                exploit = module()