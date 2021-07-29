import platform
from .Controller import Controller


class HomeController(Controller):

    def DetectionSystem(self):
        """Détection du system Host et lance le script approprier """

        if platform.system() == "Linux":
            self.LinuxStartScript()

        elif platform.system() == "Windows":
            self.WindowsStartScript()
        else:
            self.view.NoPlatformSupport


    def WindowsStartScript(self):
        pass


    def LinuxStartScript(self):
        pass