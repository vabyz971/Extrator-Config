import tkinter as tk
import os
import json

from Views.Widget import NavBar, DisclaimerPage, SettingPage, BaseWindow
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
            frame = page(parent=main_frame)
            self.frames[page] = frame
            frame.place(rely=0, relx=0)

        self.show_frame(MainPage)

    def show_frame(self, frame_name):
        """Affiche la page passer en parameter."""
        frame = self.frames[frame_name]
        frame.tkraise()

    def OpenSettingPage(self):
        SettingPage(parent=self)

    def OpenDisclaimerPage(self):
        DisclaimerPage(parent=self)


class Setting():

    def __init__(self):
        self.APP = []
        self.GUI = []
        self.THEME = []
        self.MODE_DARK = 0
        self.LANG = []

        self.InitSettings()

    def InitSettings(self):
        """Chargement du fichier setting.json"""
        with open(os.path.join('setting.json')) as Settings:
            data = json.load(Settings)
            self.APP = data['APP']
            self.GUI = data['GUI']
            self.MODE_DARK = data['GUI']['MODE_DARK']

            # check le dark mode dans le fichier setting.json
            if self.MODE_DARK == 1:
                self.THEME = data['GUI']['THEME_DARK']
            else:
                self.THEME = data['GUI']['THEME_LIGHT']

            if self.APP['LANG']:
                self.InitLanguages()
            else:
                print("Folder is not exist")


    def InitLanguages(self):
        """Chargement du language dans le fichier setting.json"""
        with open(os.path.join('lang',self.APP['LANG']+ ".json"), 'r', encoding='utf8') as lang:
            data = json.load(lang)
            self.LANG = data


if __name__ == "__main__":
    setting = Setting()
    root = Application()
    root.mainloop()
