# /**
#  * @author [Jahleel Lacascade]
#  * @email [j.lacascade@mail.com]
#  * @create date 2021-06-18 10:37:22
#  * @modify date 2021-06-18 10:37:22
#  */



import platform
import os
import re
import subprocess
import locale

from tools import Mylib
import i18n


class Application():

    filesOS = []
    i18n = i18n.returnLanguageSystem()

    def Initialisation(self):

        print("*"*5, self.i18n['START'] , "*"*5)
        self.DetectionSysteme()

    def DetectionSysteme(self):
        """Détection du system Host et lance le script approprier """

        self.ListFileSystemOS()

        print("System  :", platform.system(), self.i18n['BASE']['detected'])
        print("Language:", locale.getdefaultlocale()[0], self.i18n['BASE']['detected'])
        
        if platform.system() == "Linux":
            self.LinuxDetecter()

        elif platform.system() == "Windows":
            self.WindowsDetecter()

        else:
            print(str(self.i18n['ERROR']['no_charge_sytem']).format(platform.system(), platform.release()))
            return False

    def LinuxDetecter(self):
        """Vérification du system linux detecter """

        choix = str(input("utiliser le Benchmarck par défault y/n: "))

        if choix == "y" or choix == "Y":
            
            os_release = dict(Mylib.read_os_releases())

            for n, f in enumerate(self.filesOS):
                if(re.search(os_release.get('ID')+"_"+os_release.get('VERSION_ID'), f)):
                    subprocess.run(['python', f])
                else:
                    print("Votre system", platform.system(), platform.release() ,"na pas encore de CIS benchmarck ")
 

        elif choix == "n" or choix == "N":
            for n, f in enumerate(self.filesOS):
                print(n, ":", f)

            choixBench = int(input("Entre le numero: "))
            subprocess.run(['python', self.filesOS[choixBench]])

    def WindowsDetecter(self):
        """Vérification du systeme windows détection"""
        
        choix = str(input(str(self.i18n['INPUT']['choise_benchmarck'])))

        if choix == "y" or choix == "Y":
            
            for n,f in enumerate(self.filesOS):
                if(re.search(platform.win32_ver()[0], f)):
                    subprocess.run(['python',f])
                else:
                    print(str(self.i18n['ERROR']['no_benchmarck_system']).format(platform.system(), platform.release()))

        elif choix == "n" or choix == "N":
            for n, f in enumerate(self.filesOS):
                print(n, ":", f)

            choixBench = int(input(self.i18n['INPUT']['enter_number']))
            subprocess.run(['python', self.filesOS[choixBench]])

    def ListFileSystemOS(self):
        """Liste tout le repertoire lier a la platform (Linux/ Windows)
        dans le dossier ./CIS

        Returns:
            [Array]: [Tableau de type str] chemin absolute des fichiers
        """

        for path in os.listdir(os.path.join('CIS', platform.system())):
            full_path = os.path.join('CIS', platform.system(), path)
            if os.path.isfile(full_path):
                self.filesOS.append(full_path)


if __name__ == '__main__':
    app = Application()
    app.Initialisation()
