import locale
import platform
import tkinter as tk
import os
import json

from Views.Widget import NavBar, DisclaimerPage, SettingPage
from Views.HomePage import MainPage


class Application(tk.Tk):

    # Initialisation de la fenetre
    def __init__(self):
        super().__init__()
        self.SETTING = setting
        self.title("Extractor Configuration")
        main_frame = tk.Frame(self, width=setting.GUI['WIDTH'],  height=setting.GUI['HEIGHT'])
        main_frame.pack_propagate(0)
        main_frame.pack(fill="both", expand=True)
        self.resizable(0, 0)
        self.geometry(f"{setting.GUI['WIDTH']}x{setting.GUI['HEIGHT']}")

        # Menu de l'applications
        menubar = NavBar(parent=self)
        self.config(menu=menubar)

        # Frame de l'applications
        self.frames = {}
        pages = (MainPage,)  # TODO Liste des Pages

        for page in pages:
            frame = page(parent=main_frame, setting=self.SETTING)
            self.frames[page] = frame
            frame.place(rely=0, relx=0)

        self.show_frame(MainPage)

    def show_frame(self, frame_name):
        """Affiche la page passer en parameter."""
        frame = self.frames[frame_name]
        frame.tkraise()

    def ChangeLanguageAndTheme(self, args={}):
        """Récuper un tableau d'argument pour l'envoie a la class setting"""
        if args is not None:
            setting.ChangeSetting(args)

    def OpenSettingPage(self):
        SettingPage(parent=self)

    def OpenDisclaimerPage(self):
        DisclaimerPage(parent=self)


class Setting():
    """Class qui stock l'ensemble des paramètre du fichier setting.json"""

    def __init__(self):
        self.APP = []
        self.GUI = []
        self.THEME = []
        self.MODE_DARK = 0
        self.LANG = []

        self.InitSettings()
        self.InitLanguages()

    def InitSettings(self):
        """Chargement du fichier setting.json"""
        with open(os.path.join('setting.json')) as Settings:
            data = json.load(Settings)
            self.APP = data['APP']
            self.GUI = data['GUI']
            self.MODE_DARK = data['GUI']['MODE_DARK']

            # check le dark mode si il est Activer dans le fichier setting.json
            if self.MODE_DARK == 1:
                self.THEME = data['GUI']['THEME_DARK']
            else:
                self.THEME = data['GUI']['THEME_LIGHT']

            if self.APP["AUTO_LANG"] == 1 and platform.system() == "Windows":
                self.APP["LANG"] = locale.getdefaultlocale()[0]
            elif self.APP["AUTO_LANG"] == 1 and platform.system() == "Linux":
                self.APP["LANG"] = os.getenv('LANG')


    def InitLanguages(self):
        """Chargement du language dans le fichier setting.json"""
        with open(os.path.join('lang', self.APP['LANG'] + ".json"), 'r', encoding='utf8') as lang:
            data = json.load(lang)
            self.LANG = data

    def ChangeSetting(self, args={}):
        data = []

        #Récuper tout le fichier setting.json pour le stocké dans data
        with open(os.path.join('setting.json'), 'r', encoding='utf8')as r_file:
            data = json.load(r_file)

        #Réécrie les donnéés avant de les sauvegarders
        with open(os.path.join('setting.json'), 'w') as w_file:
            try:
                data["APP"]["LANG"] = args["LANG"]
                data["APP"]["AUTO_LANG"] = args["AUTO_LANG"]
                data["GUI"]["MODE_DARK"] = args["MODE_DARK"]

                json.dump(data, w_file)
            except print(0):
                print("File Setting no save")



if __name__ == "__main__":
    setting = Setting()
    root = Application()
    root.mainloop()
