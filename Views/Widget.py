import tkinter as tk
from tkinter import *
from tkinter import messagebox

class NavBar(tk.Menu):
    """ Barre de Navigation 
    """

    def __init__(self, parent):
        super().__init__(parent)

        # Option
        menu_option = tk.Menu(self, tearoff=0)
        self.add_cascade(
            label=parent.SETTING.LANG['SYSTEM']['parameter'], menu=menu_option)
        menu_option.add_command(
            label=parent.SETTING.LANG['SYSTEM']['option'], command=parent.OpenSettingPage)
        menu_option.add_command(
            label=parent.SETTING.LANG['SYSTEM']['about'], command=parent.OpenDisclaimerPage)
        menu_option.add_separator()
        menu_option.add_command(
            label=parent.SETTING.LANG['SYSTEM']['exit'], command=parent.quit)

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
        self.parent = parent
        self.geometry("400x200")
        self.title(parent.SETTING.LANG['SYSTEM']['option'])

        #Contener padding
        self.base_frame.pack(padx=5, pady=20)

        # Language
        label_language = Label(
            self.base_frame, text=parent.SETTING.LANG['SYSTEM']['language'] + ':', font=('Arial', 10), width=10)
        label_language.grid(row=0, column=0)

        # CheckBox Auto Language System
        self.check_langAuto_Var = IntVar()
        self.check_langAuto_Var.set(parent.SETTING.APP['AUTO_LANG'])
        check_langAuto = Checkbutton(self.base_frame, text=parent.SETTING.LANG['active_detected_language'],
                                     variable=self.check_langAuto_Var)
        check_langAuto.grid(row=0, column=2)

        #Récuper la string dans le tableau language
        self.drop_language_Var = StringVar()
        self.drop_language_Var.set(parent.SETTING.APP['LANG'])

        #List des languages dans le fichier lang
        language = ["fr_FR", "en_EN"]

        #Selection de la langue et la stock dans (drop_language_Var)
        drop_language = OptionMenu(
            self.base_frame, self.drop_language_Var, *language)
        drop_language.grid(row=0, column=1)

        # Theme App
        label_theme = Label(self.base_frame, text="Theme:",
                            font=("Arial", 10), width=10)
        label_theme.grid(row=1, column=0)

        # Checkbox Theme dark
        self.check_theme_Var = IntVar()
        self.check_theme_Var.set(parent.SETTING.GUI['MODE_DARK'])
        check_theme = Checkbutton(self.base_frame, text=parent.SETTING.LANG['mode_dark'], variable=self.check_theme_Var)
        check_theme.grid(row=1, column=1)

        # Btn Submit
        btn_valide_theme = Button(
            self.base_frame, text="Appliquer", command=self.CommitDataSetting)
        btn_valide_theme.grid(row=3, column=1)

    def CommitDataSetting(self):
        data = {
                "LANG":self.drop_language_Var.get(),
                "MODE_DARK":self.check_theme_Var.get(),
                "AUTO_LANG": self.check_langAuto_Var.get()}

        self.parent.ChangeLanguageAndTheme(data)
        messagebox.showinfo(title=self.parent.SETTING.LANG["INDEX"]["system"],
                            message=self.parent.SETTING.LANG["WARNING"]["warning"],
                            detail=self.parent.SETTING.LANG["WARNING"]["restart_application_change"]
                            )

class DisclaimerPage(BaseWindow):
    """ Page du à propos
    """
    def __init__(self, parent):
        super().__init__()
        self.title(parent.SETTING.LANG['SYSTEM']['about'])
        self.geometry("400x200")
        label_title = Label(self.base_frame, text=parent.SETTING.LANG["START"], font=('Arial Bold', 11))
        label_title.grid(row=0, column=0, columnspan=2, pady=15, padx=50)

        label_createBy = Label(self.base_frame, text="Create by:")
        label_createBy.grid(row=1, column=0)
        label_author = Label(self.base_frame, text=parent.SETTING.APP["AUTHOR"]["NAME"])
        label_author.grid(row=1, column=1)

        label_email = Label(self.base_frame, text="Email:")
        label_email.grid(row=2, column=0)
        label_author_email = Label(self.base_frame, text=parent.SETTING.APP["AUTHOR"]["EMAIL"])
        label_author_email.grid(row=2, column=1)

        label_version = Label(self.base_frame, text="version:")
        label_version.grid(row=3, column=0)
        label_version_current = Label(self.base_frame, text=parent.SETTING.APP['VERSION'])
        label_version_current.grid(row=3, column=1)
