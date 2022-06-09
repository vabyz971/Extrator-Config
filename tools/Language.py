
import locale, os, json

def langDetected():
    """Detection de la langue du system"""
    f = open(os.path.join('Language', locale.getdefaultlocale()[0] + ".json"), 'r', encoding='utf8')
    return json.loads(f.read())
