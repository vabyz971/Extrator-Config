import tkinter as tk

from Controllers.Home import HomeController

class MainPage(tk.Frame):
    def __init__(self,parent):
        super().__init__(parent)

        self.controller = HomeController(view=self)

        
        
