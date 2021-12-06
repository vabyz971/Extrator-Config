
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
        print(f'{self.OKGREEN}[ OK ] - {message}{self.ENDC}')

    def pFailure(self, message):
        print(f'{self.FAIL}[ FAIL ] - {message}{self.ENDC}')

    def pWarning(self, message):
        print(f'{self.WARNING}[ WARNING ] - {message}{self.ENDC}')

    def pHeader(self, message):
        print(f'{self.HEADER} === {self.BOLD}{message} === {self.ENDC}')
    
    def pBleu(self, message):
        print(f'{self.OKBLUE} {message} {self.ENDC}')

class CIS():

    def Main(self):
        self.Color = bcolors()
        self.Manifest()
        self.InitialSetup()

    def Manifest(self):
        self.name = "Benshmarck ubuntu"
        self.author = "Jahleel Lacascade"
        self.email = "jahleel.lacascade@caerus.com"
        self.version = "0.16.2" 
        self.url_CIS_benchmark = "https://learn.cisecurity.org/l/799323/2021-04-01/41hcb"

        self.Color.pHeader("="*5+ "Manifest" + "="*5)
        self.Color.pBleu("Name   : " +self.name)
        self.Color.pBleu("Author : " +self.author)
        self.Color.pBleu("Email  : " +self.email)
        self.Color.pBleu("Version: " +self.version)
        print("CIS Benshmarck", ":", self.url_CIS_benchmark)

    def InitialSetup(self):
        self.FilesystemConfiguration()

    def FilesystemConfiguration(self):
        self.Ensure_mounting_of_module_filesystem_is_disabled()
        self.Ensure_tmp_is_configured()
        self.Ensure_module_option_set_on_tmp_partition()
        self.Ensure_dev_shm_is_configured()
        self.Ensure_module_option_set_on_dev_shm_partition()
        self.Disable_automounting()
        self.Disable_usb_storage()
        self.Ensure_package_manager_repositories_are_configured()
        self.Ensure_GPG_keys_are_configured()
        self.Ensure_AIDE_is_installed()
        self.Ensure_filesystem_integrity_is_regularly_checked()
        self.Ensure_filesystem_integrity_is_regularly_checked()
        self.Ensure_permissions_bootloader_config_are_not_overridden()
        self.Ensure_bootloader_password_is_set()
        self.Ensure_permissions_on_bootloader_config_are_configured()
        self.Ensure_authentication_required_for_single_user_mode()

    def Ensure_mounting_of_module_filesystem_is_disabled(self):
        modules = ["cramfs","freevxfs","jffs2","hfs","hfsplus","udf"]
        self.Color.pHeader(f"Ensure mounting of {modules} filesystems is disabled")

        IsRemediation = False;

        for module in modules:
            command_modprobe = subprocess.run([f"modprobe -n -v {module} | grep -E '({module}|install)'",], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if(command_modprobe.returncode == 0):
                self.Color.pSuccess(module + " Install")
                IsRemediation = False;
                
                command_lsmod = subprocess.run(["lsmod | grep", module],  shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if(command_lsmod.stdout is None):
                    return

            else:
                self.Color.pFailure(command_modprobe.stderr)
                IsRemediation = True;

            if(IsRemediation):
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

    def Ensure_tmp_is_configured(self):
        #TODO: remediation tmp is configured
        self.Color.pHeader(f"Ensure /tmp is configured")

        command_findmnt = subprocess.run(['findmnt /tmp'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if(command_findmnt.stdout):
            self.Color.pSuccess(command_findmnt.stdout)
        
        self.Color.pWarning("Partition /tmp no detecte")

    def Ensure_module_option_set_on_tmp_partition(self):
        #TODO: finish the remediation module that uses /tmp
        modules = ["nodev","nosuid","noexec"]

        IsRemediation = False

        for module in modules:
            command_findmnt = subprocess.run([f"findmnt -n /tmp | grep -v {module}"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if(command_findmnt.returncode == 0):
                if(command_findmnt.stdout):
                    self.Color.pSuccess(f"{module} is OK")
                else:
                    IsRemediation = True
            
            if(IsRemediation):
                self.Color.pWarning(f"[REMEDIATION] Ensure {module} option set on /tmp partition")

    def Ensure_dev_shm_is_configured(self):
        
        #TODO: Add Parameter additional dev/shm Configured

        command_findmnt = subprocess.run("findmnt /dev/shm", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if(command_findmnt.returncode == 0):
            self.Color.pSuccess("dev/shm Detecte")
            print(command_findmnt.stdout)
        else:
            self.Color.pFailure(command_findmnt.stderr)
        
        self.Color.pWarning(f"[REMEDIATION] Ensure /dev/shm configured ")
        isActive = int(input("1:yes | 0:no => "))

        if(isActive == 1):
            File = os.path.isfile(f"/etc/fstab")
            if(File):
                with open(File,'a') as file:
                    file.write("tmpfs   /dev/shm    tmpfs   defaults,noexec,nodev,nosuid,seclabel   0 0")
                    file.close()
                
                command_mounter = subprocess.run("mount -o remount,noexec,nodev,nosuid /dev/shm",shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if(command_mounter.returncode == 0):
                    self.Color.pSuccess("dev/shm is mounted")
                else:
                    self.Color.pFailure(command_mounter.stderr)
        else:
            pass

    def Ensure_module_option_set_on_dev_shm_partition(self):

        modules = ["nodev","nosuid", "noexec"]
        self.Color.pHeader(f"Ensure {modules} option set on /dev/shm partition")

        for module in modules:
            command_findmnt = subprocess.run([f"findmnt -n /dev/shm | grep -v {module}"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if(command_findmnt.returncode == 0):
                self.Color.pSuccess(module + " Verify")
            else:
                self.Color.pWarning(command_findmnt.stdout)
                #TODO: Add Remediation option set on /dev/shm partition

    def Disable_automounting(self):
        self.Color.pHeader("Disable Automounting")

        command_dpkg = subprocess.run("dpkg -s autofs", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if(command_dpkg.returncode == 1):
            self.Color.pSuccess("Auto mounted is not install")
        else:
            self.Color.pWarning(f"[REMEDIATION] Disable Automounting Remove")
            isActive = int(input("1:yes | 0:no => "))
            if(isActive == 1):
                command_purge_autofs = subprocess.run("apt purge autofs", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if(command_purge_autofs.returncode == 0):
                    self.Color.pSuccess("autofs is uninstall")
            else:
                pass

    def Disable_usb_storage(self):
        self.Color.pHeader("Disable USB Storage")

        command_modprobe = subprocess.run("modprobe -n -v usb-storage", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if(command_modprobe.returncode == 0):
            self.Color.pSuccess("usb-storage Detected")
        
        if(command_modprobe.stdout.count == 0):
            self.Color.pSuccess("lsmod usb-storage is Ok")
        else:
            self.Color.pWarning(f"[REMEDIATION] Disable USB Storage")
            isActive = int(input("1:yes | 0:no => "))
            if(isActive == 1):
                usb_storageFile = os.path.isfile("/etc/modprobe.d/usb_storage.conf")
                if(usb_storageFile):
                    with open(usb_storageFile, 'a') as file:
                        file.write("install usb-storage /bin/true")
                        file.close()
                        command_rmmod = subprocess.run("rmmod usb-storage", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        if(command_rmmod.returncode == 0):
                            self.Color.pSuccess(command_rmmod.stdout)
                else:
                    with open(usb_storageFile, 'r') as file:
                        file.write("install usb-storage /bin/true")
                        file.close()
                        command_rmmod = subprocess.run("rmmod usb-storage", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        if(command_rmmod.returncode == 0):
                            self.Color.pSuccess(command_rmmod.stdout)
            else:
                pass

    def Ensure_package_manager_repositories_are_configured(self):
        self.Color.pHeader("Ensure package manager repositories are configured")

        command_apt = subprocess.getoutput('apt-cache policy')
        if(command_apt):
            print(command_apt)
    
    def Ensure_GPG_keys_are_configured(self):
        self.Color.pHeader("Ensure GPG keys are configured")

        command_apt = subprocess.getoutput('apt-cache policy')
        if(command_apt):
            print(command_apt)

    def Ensure_AIDE_is_installed(self):
        self.Color.pHeader("Ensure AIDE is installed")
        modules = ["aide","aide-common"]

        isRemediation = False;

        for module in modules:
            command_dpkg = subprocess.run(f"dpkg -s {module} | grep -E '(Status:|not installed)'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if(command_dpkg.returncode == 0):
                self.Color.pSuccess(f"{module} ok installed")
                isRemediation = False
            else:
                self.Color.pWarning(f"{module} not installed")
                isRemediation = True
                break
        
        if(isRemediation):
            self.Color.pWarning(f"[REMEDIATION] Ensure AIDE is installed")

            isActive = input("1:yes | 0:no => ")
            if(isActive == 1 or isActive == "yes" or isActive == "y"):
                command_apt = subprocess.run("apt install aide aide-common", shell=True, stdout=subprocess.PIPE)
                if(command_apt.returncode == 0):
                    print(command_apt.stdout)
                    command_aide = subprocess.run("aideinit", shell=True, stdout=subprocess.PIPE)
                    if(command_aide.returncode == 0):
                        mv = "mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
                        command_mv = subprocess.run(mv)
                        if(command_mv.returncode == 0):
                            self.Color.pSuccess("Remediation Finis")
                            isRemediation = False
            else:
                pass

    def Ensure_filesystem_integrity_is_regularly_checked(self):
        self.Color.pHeader("Ensure filesystem integrity is regularly checked")
        isRemediation = False;
        command_systemctl = subprocess.run("systemctl is-enabled aidecheck.service", shell=True , stdout=subprocess.PIPE)

        if(command_systemctl.returncode != 0):
            command_systemctl = subprocess.run("systemctl is-enabled aidecheck.timer", shell=True, stdout=subprocess.PIPE)
            self.Color.pSuccess(command_systemctl.stdout)
            command_systemctl = subprocess.run("systemctl status aidecheck.timer", shell=True, stdout=subprocess.PIPE)
            self.Color.pSuccess(command_systemctl.stdout)
        else:
            isRemediation = True

        if(isRemediation):
            pass
            #TODO: Remediation filesystem integrity is regularly checked no complete

    def Ensure_permissions_bootloader_config_are_not_overridden(self):
        pass
        #TODO: Ensure permissions on bootloader config are not overridden

    def Ensure_bootloader_password_is_set(self):
        pass
        #TODO: Ensure bootloader password is set

    def Ensure_permissions_on_bootloader_config_are_configured(self):
        pass
        #TODO: Ensure permissions on bootloader config are configured

    def Ensure_authentication_required_for_single_user_mode(self):
        self.Color.pHeader("Ensure authentication required for single user mode")

        command_grep = subprocess.run(["grep -Eq '^root:\$[0-9]' /etc/shadow || echo 'root is locked'"], shell=True, stdout=subprocess.PIPE)
        
        isRemediation = False

        if(command_grep.returncode == 0):
            self.Color.pSuccess("Password root")
            isRemediation = False
        else:
            isActive = int(input("1:yes | 0:no => "))
            if(isActive == 1):
                isRemediation = True
        
        if(isRemediation):
            command_passwd = subprocess.Popen("passwd root", shell=False,stdin=subprocess.PIPE , stdout=subprocess.PIPE)
            if(command_passwd.returncode == 0):
                newPass = str(input(command_passwd.stdout))
                command_passwd.stdin.write(newPass)
                self.color.pSuccess(command_passwd.stdout)
                isRemediation = False


if __name__ == "__main__":
    ubuntu_ = CIS()
    ubuntu_.Main()
