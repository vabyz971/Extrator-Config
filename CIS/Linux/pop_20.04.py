

class CIS():

    def Main(self):
        self.Manifest()
    
    def Manifest(self):
        self.name = "Benshmarck Pop-OS"
        self.author = "Jahleel Lacascade"
        self.email = "jahleel.lacascade@caerus.com"
        self.version = "0.1"
        self.url_CIS_benchmark = "https://learn.cisecurity.org/l/799323/2021-04-01/41hcb"

        print("="*5, "Manifest", "="*5)
        print("Name   ",":", self.name)
        print("Author ",":", self.author)
        print("Email  ",":", self.email)
        print("Version",":", self.version)
        print("CIS Benshmarck",":", self.url_CIS_benchmark)




if __name__ == "__main__":
    pop_ = CIS()
    pop_.Main()