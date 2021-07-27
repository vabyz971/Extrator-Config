import tkinter as tk
from tkinter import *


class NavBar(tk.Menu):
    """ Barre de Navigation 
    """

    def __init__(self, parent):
        super().__init__(parent)

        # Option
        menu_option = tk.Menu(self, tearoff=0)
        self.add_cascade(label=parent.SETTING.LANG['SYSTEM']['parameter'], menu=menu_option)
        menu_option.add_command(
            label=parent.SETTING.LANG['SYSTEM']['option'], command=parent.OpenSettingPage)
        menu_option.add_command(
            label=parent.SETTING.LANG['SYSTEM']['about'], command=parent.OpenDisclaimerPage)
        menu_option.add_separator()
        menu_option.add_command(label=parent.SETTING.LANG['SYSTEM']['exit'], command=parent.quit)


class BaseWindow(tk.Toplevel):
    """
    Classe pour faire de l'éritage pour 
    les sous fenètres de l'application  
    """

    def __init__(self):
        super().__init__()
        self.base_frame = tk.Frame(self)
        self.base_frame.pack_propagate(0)
        self.base_frame.pack(fill="both", expand=True)
        self.fonts = ("sans-serif", 9)
        self.geometry("600x200")
        self.resizable(0, 0)


class SettingPage(BaseWindow):
    """ Page des Options de l'application 
    """

    def __init__(self, parent):
        super().__init__()
        self.title(parent.SETTING.LANG['SYSTEM']['option'])

        # Language
        label_language = Label(
            self.base_frame, text="Language:", font=('Arial', 10), width=12)
        label_language.grid(row=0, column=0)

        self.drop_language_Var = StringVar()
        self.drop_language_Var.set("Français")
        drop_language = OptionMenu(
            self.base_frame, self.drop_language_Var, 'Français', 'Anglais')
        drop_language.grid(row=0, column=1)

        # Theme App
        label_theme = Label(self.base_frame, text="Theme:",
                            font=("Arial", 10), width=12)
        label_theme.grid(row=1, column=0)

        self.drop_theme_Var = StringVar()
        self.drop_theme_Var.set('Light')

        drop_theme = OptionMenu(
            self.base_frame, self.drop_theme_Var, 'Light', 'Dark')
        drop_theme.grid(row=1, column=1)

        # Btn Submit
        btn_valide_theme = Button(
            self.base_frame, text="Appliquer", command=self.SubmitChangeValue)
        btn_valide_theme.grid(row=1, column=2)

    def SubmitChangeValue(self):
        pass


class DisclaimerPage(BaseWindow):
    """ Page du à propos
    """

    def __init__(self, parent):
        super().__init__()
        self.title(parent.SETTING.LANG['SYSTEM']['about'])
        self.geometry("300x300")
        summer = 'bla bla'
        frame_disc = tk.LabelFrame(self.base_frame, text='disclaime')
        frame_disc.pack(expand=True, fill="both")
        label_disc = tk.Label(frame_disc, text=summer, font=self.fonts)
        label_disc.pack(expand=True)

        label_version = Label(frame_disc, text="version:0.1.2", font=('', 8))
        label_version.pack()
