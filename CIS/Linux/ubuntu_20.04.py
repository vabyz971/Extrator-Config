
import subprocess


class CIS():

    def Main(self):
        self.Manifest()
        self.ConfigSoftwareUpdate()
        self.NetworkConfigurations()
    
    def Manifest(self):
        self.name = "Benshmarck ubuntu"
        self.author = "Jahleel Lacascade"
        self.email = "jahleel.lacascade@caerus.com"
        self.version = "0.1"
        self.url_CIS_benchmark = "https://learn.cisecurity.org/l/799323/2021-04-01/41hcb"

        print("\n")
        print("="*4, "Manifest", "="*3)
        print("Name   ",":", self.name)
        print("Author ",":", self.author)
        print("Email  ",":", self.email)
        print("Version",":", self.version)
        print("CIS Benshmarck",":", self.url_CIS_benchmark)


    def ConfigSoftwareUpdate(self):
        self.ConfigGestionnairePaquets()
        self.ConfigKeyGPG()

    def ConfigGestionnairePaquets(self):
        """ Verification de la configuration du gestionnaire de paquets 
        
        * Niveau 1 : serveur
        * Niveau 1 : Station de travail
        """
        print('\n',"*"*3,"Configuration du gestionnaire de paquets","*"*3,'\n')
        print(subprocess.getoutput('apt-cache policy'))

    def ConfigKeyGPG(self):
        """ Verification de la configuration des Key GPG 
        
        * Niveau 1 : serveur
        * Niveau 1 : Station de travail
        """
        print('\n',"*"*3,"Configuration des clés GPG","*"*3, '\n')
        print(subprocess.getoutput('apt-key list'))



    def NetworkConfigurations(self):
        self.DisableIPv6();

    
    def DisableIPv6(self):
        """ Desactivation de IPv6

        * Niveau 2 : serveur
        * Niveau 2 : Station de travail
        """

        print(subprocess.getoutput('AddressFamily inet'))


if __name__ == "__main__":
    ubuntu_ = CIS()
    ubuntu_.Main()