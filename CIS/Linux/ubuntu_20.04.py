
import os
import subprocess


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    def pSuccess(self, message):
        print(f'{self.OKGREEN}{message}{self.ENDC}')

    def pFailure(self, message):
        print(f'{self.FAIL}{message}{self.ENDC}')

    def pWarning(self, message):
        print(f'{self.WARNING}{message}{self.ENDC}')

    def pHeader(self, message):
        print(f'{self.HEADER}{self.BOLD}{message}{self.ENDC}')

class CIS():

    def Main(self):
        self.Color = bcolors()
        self.Manifest()
        self.InitialSetup()
        self.ConfigSoftwareUpdate()
        self.NetworkConfigurations()

    def Manifest(self):
        self.name = "Benshmarck ubuntu"
        self.author = "Jahleel Lacascade"
        self.email = "jahleel.lacascade@caerus.com"
        self.version = "0.1.1"
        self.url_CIS_benchmark = "https://learn.cisecurity.org/l/799323/2021-04-01/41hcb"

        print("\n")
        print("="*4, "Manifest", "="*3)
        print("Name   ", ":", self.name)
        print("Author ", ":", self.author)
        print("Email  ", ":", self.email)
        print("Version", ":", self.version)
        print("CIS Benshmarck", ":", self.url_CIS_benchmark)

    def InitialSetup(self):
        self.FilesystemConfiguration()

    def FilesystemConfiguration(self):
        self.Ensure_Mounting_of_Module_Filesystem_is_disabled()
        if(self.Ensure_tmp_is_Configured()):
            self.Ensure_Module_Option_set_on_tmp_Partition()
        if(self.Ensure_dev_shm_is_Configured()):
            pass

    def Ensure_Mounting_of_Module_Filesystem_is_disabled(self):
        modules = ["cramfs","freevxfs","jffs2","hfs","hfsplus","udf"]
        self.Color.pHeader(f"Ensure mounting of {modules} filesystems is disabled")

        for module in modules:
            command_modprobe = subprocess.run([f"modprobe -n -v {module} | grep -E '({module}|install)'",], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if(command_modprobe.returncode == 0):
                self.Color.pSuccess(module + " Install")
                print(command_modprobe.stdout)
            else:
                self.Color.pFailure(command_modprobe.stderr)

            command_lsmod = subprocess.run(["lsmod | grep", module],  shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if(command_lsmod.stdout):
                self.Color.pSuccess(module + " activate")
            else:
                self.Color.pWarning(f"[REMEDIATION] Ensure mounting of {module} filesystems is disabled ")

                isActive = int(input("1:yes | 0:no => "))
                if(isActive == 1):
                    moduleFile = os.path.isfile(f"/etc/modprobe.d/{module}.conf")
                    if(moduleFile):
                        #Add ligne file is exist
                        with open(moduleFile, 'a') as file:
                            file.write(f"install {module} /bin/true")
                            file.close()
                    else:
                        #Create File is not exist
                        #Start Script is Admin Obligation
                        with open(moduleFile, 'w') as file:
                            file.write(f"install {module} /bin/true")
                            file.close()
                    
                    command_rmmod = subprocess.run([f"rmmod {module}"],stdout=subprocess.PIPE)
                    if(command_rmmod.stdout):
                        self.Color.pSuccess(f"{module} start")
                    else:
                        self.Color.pFailure(f"{module} unload")
                        self.Color.pWarning(command_rmmod.stdout)
                else:
                    pass

    def Ensure_tmp_is_Configured(self):
        #TODO: remediation tmp is configured
        self.Color.pHeader(f"Ensure /tmp is configured")

        command_findmnt = subprocess.run(['findmnt /tmp'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if(command_findmnt.stdout):
            self.Color.pSuccess(command_findmnt.stdout)
            return True
        
        self.Color.pWarning("Partition /tmp no detecte")
        return False

    def Ensure_Module_Option_set_on_tmp_Partition(self):
        #TODO: finish the remediation module that uses /tmp
        modules = ["nodev","nosuid","noexec"]

        for module in modules:
            command_findmnt = subprocess.run([f"findmnt -n /tmp | grep -v {module}"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if(command_findmnt.returncode == 0):
                if(command_findmnt.stdout):
                    self.Color.pSuccess(f"{module} is OK")

    def Ensure_dev_shm_is_Configured(self):
        pass

    def ConfigSoftwareUpdate(self):
        self.ConfigGestionnairePaquets()
        self.ConfigKeyGPG()

    def ConfigGestionnairePaquets(self):
        """ Verification de la configuration du gestionnaire de paquets 

        * Niveau 1 : serveur
        * Niveau 1 : Station de travail
        """
        print('\n', "*"*3, "Configuration du gestionnaire de paquets", "*"*3, '\n')
        print(subprocess.getoutput('apt-cache policy'))

    def ConfigKeyGPG(self):
        """ Verification de la configuration des Key GPG 

        * Niveau 1 : serveur
        * Niveau 1 : Station de travail
        """
        print('\n', "*"*3, "Configuration des clés GPG", "*"*3, '\n')
        print(subprocess.getoutput('apt-key list'))

    def NetworkConfigurations(self):
        self.DisableIPv6()

    def DisableIPv6(self):
        """ Desactivation de IPv6

        * Niveau 2 : serveur
        * Niveau 2 : Station de travail
        """

        print(subprocess.getoutput('AddressFamily inet'))


if __name__ == "__main__":
    ubuntu_ = CIS()
    ubuntu_.Main()
