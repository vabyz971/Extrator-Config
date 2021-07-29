import platform
import tkinter as tk
from tkinter import LabelFrame, Label, messagebox

from Controllers.Home import HomeController

class MainPage(tk.Frame):
    def __init__(self, parent, setting):
        super().__init__(parent)
        self.setting = setting

        self.controller = HomeController(view=self)
        self.controller.DetectionSystem()


        ##########################################:: INTERFACE ::####################################

        #Frame information sur la platform
        frame_InfoSystem = LabelFrame(parent, text=setting.LANG["info_platform"])
        frame_InfoSystem.grid(pady=10, padx=10)

        label_PlatformSystem = Label(frame_InfoSystem, text=str("• " + setting.LANG["system_detected"]).format(platform.system() + " " + platform.release()))
        label_PlatformSystem.pack(padx=5, pady=5)

        label_BuildSystem = Label(frame_InfoSystem,text=str("• "+"Build: " + platform.version()))
        label_BuildSystem.pack(padx=5, pady=5)

        ##########################################:: END INTERFACE ::####################################

        ##########################################:: FUNCTION ::####################################

    def IsAutoStartScriptPlatform(self):
        """Si dans le controller,si il exist un script pour la platform en question
            ont demande a l'utilisateur de choisir si ont veux exécuter
            [Return] Boolean
        """
        msg_IsAutoScrip = messagebox.askyesnocancel(title=self.setting.LANG["WARNING"]["information"],
                                                 message=self.setting.LANG["WARNING"]["is_detect_scrip_auto_start"])

        return msg_IsAutoScrip


    def NoPlatformSupport(self):
        """Affiche un messageBox pour avertir que le script n'est pas compatible"""

        msgBox_PlatformNoSupport = messagebox.askyesnocancel(title=self.setting.LANG["ERROR"]["error"],
                                                             message=self.setting.LANG["ERROR"]["no_support_platform"])
        return msgBox_PlatformNoSupport
        ##########################################:: END FUNCTION ::####################################
