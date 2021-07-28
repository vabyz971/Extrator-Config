import platform
import tkinter as tk
from tkinter import *

from Controllers.Home import HomeController

class MainPage(tk.Frame):
    def __init__(self, parent, setting):
        super().__init__(parent)
        self.controller = HomeController(view=self)

        label_SystemDetected = Label(parent, text=str(setting.LANG["system_detected"]).format(platform.system()))
        label_SystemDetected.pack()