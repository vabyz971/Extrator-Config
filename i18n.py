
import locale, platform, os, json


def returnLanguageSystem():
    """Détection de la langue du system"""
    f = open(os.path.join('lang', locale.getdefaultlocale()[0] + ".json"), 'r', encoding='utf8')
    return json.loads(f.read())