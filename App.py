
import platform
import os
import re
import subprocess
import locale

from tools import libCreate
from tools import Language
from tools import HUDShell as HUD


class Application():

    filesOS = []
    i18n = Language.langDetected()

    def Initialisation(self):
        print(self.i18n['start'])
        self.DetectionSysteme()

    def DetectionSysteme(self):
        """Détection du system Host et lance le script approprier """
        self.ListFileSystemOS()

        print("System  :", platform.system(), self.i18n['detected'])
        print("Language:", locale.getdefaultlocale()[0], self.i18n['detected'])
        
        if platform.system() == "Linux":
            self.LinuxDetecter()

        elif platform.system() == "Windows":
            self.WindowsDetecter()

        else:
            HUD.textColor(self.i18n['no_charge_sytem'].format(platform.system(), platform.release()), HUD.TypeMessage.WARNING)
            return False

    def LinuxDetecter(self):
        """Vérification du system linux detecter """

        choix = str(input("utiliser le Benchmarck par défault y/n: "))

        if choix == "y" or choix == "Y":
            
            os_release = dict(libCreate.read_os_releases())

            for n, f in enumerate(self.filesOS):
                if(re.search(os_release.get('ID')+"_"+os_release.get('VERSION_ID'), f)):
                    subprocess.run(['python3', f])
                else:
                    HUD.textColor(self.i18n['no_benchmarck_system'].format(platform.system(), platform.release()), HUD.TypeMessage.WARNING)
                    restart = str(input(str(self.i18n['restart_script'])))
                    if restart == "y" or restart == "Y":
                        self.LinuxDetecter()
                    else:
                        return
 

        elif choix == "n" or choix == "N":
            for n, f in enumerate(self.filesOS):
                print(n, ":", f)

            choixBench = int(input("Entre le numero: "))
            subprocess.run(['python3', self.filesOS[choixBench]])

    def WindowsDetecter(self):
        """Vérification du systeme windows détection"""
        
        choix = str(input(str(self.i18n['choise_benchmarck'])))

        if choix == "y" or choix == "Y":
            
            for n,f in enumerate(self.filesOS):
                if(re.search(platform.win32_ver()[0], f)):
                    subprocess.Popen(['powershell',f])
                else:
                    HUD.textColor(self.i18n['no_benchmarck_system'].format(platform.system(), platform.release()), HUD.TypeMessage.WARNING)
                    restart = str(input(str(self.i18n['restart_script'])))
                    if restart == "y" or restart == "Y":
                        self.DetectionSysteme()
                    else:
                        return

        elif choix == "n" or choix == "N":
            for n, f in enumerate(self.filesOS):
                print(n, ":", f)

            choixBench = int(input(self.i18n['enter_number']))
            subprocess.Popen(['powershell', self.filesOS[choixBench]])

    def ListFileSystemOS(self):
        """Liste tout le repertoire lier a la platform (Linux/ Windows)

        Returns:
            [Array]: [Tableau de type str] chemin absolute des fichiers
        """
        self.filesOS = []
        for path in os.listdir(os.path.join(platform.system())):
            full_path = os.path.join(platform.system(), path)
            if os.path.isfile(full_path):
                self.filesOS.append(full_path)


if __name__ == '__main__':
    app = Application()
    app.Initialisation()
