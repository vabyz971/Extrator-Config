
import locale, platform, os, json


def returnLanguageSystem():
    """Détection de la langue du system"""


    if platform.system() == "Linux":
        if os.path.join('lang', os.getenv('LANG').split(".")[0] + ".json"):
            f = open(os.path.join('lang', os.getenv('LANG').split(".")[0] + ".json"), 'r', encoding='utf8')
        else:
            f = open(os.path.join('lang', 'en_EN' + ".json"), 'r', encoding='utf8')


    elif platform.system() == "Windows":
        if os.path.join('lang', locale.getdefaultlocale()[0] + ".json"):
            f = open(os.path.join('lang', locale.getdefaultlocale()[0] + ".json"), 'r', encoding='utf8')
        else:
            f = open(os.path.join('lang', 'en_EN' + ".json"), 'r', encoding='utf8')

    return json.loads(f.read())