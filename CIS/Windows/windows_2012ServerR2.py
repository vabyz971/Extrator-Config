import subprocess
import json



class CIS():

    def Main(self):
        self.Manifest()
        self.ConfigSoftwareUpdate()
    
    def Manifest(self):
        self.name = "Benshmarck Windows 2012 server R2"
        self.author = "Jahleel Lacascade"
        self.email = "jahleel.lacascade@caerus.com"
        self.version = "0.1"
        self.url_CIS_benchmark = ""

        print("\n")
        print("="*4, "Manifest", "="*3)
        print("Name   ",":", self.name)
        print("Author ",":", self.author)
        print("Email  ",":", self.email)
        print("Version",":", self.version)
        print("CIS Benshmarck",":", self.url_CIS_benchmark)




if __name__ == "__main__":
    win2012R2 = CIS()
    win2012R2.Main()