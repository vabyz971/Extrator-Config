from enum import Enum
from .Language import langDetected


def i18n(value:str):
    return langDetected()[value]


class TypeMessage(Enum):
    SUCCESS = "success"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

class ColorTab(Enum):
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def Title(title):
    print(f"{ColorTab.BOLD.value}{title}{ColorTab.ENDC.value}")


def textColor( msg, type:TypeMessage):
    if(type == TypeMessage.INFO):
        print(f'{ColorTab.OKBLUE.value}[{i18n(TypeMessage.INFO.value)}] - {msg} {ColorTab.ENDC.value}')
    elif(type == TypeMessage.WARNING):
        print(f'{ColorTab.WARNING.value}[{i18n(TypeMessage.WARNING.value)}] - {msg} {ColorTab.ENDC.value}')
    elif(type == TypeMessage.ERROR):
        print(f'{ColorTab.FAIL.value}[{i18n(TypeMessage.ERROR.value)}] - {msg} {ColorTab.ENDC.value}')
    elif(type == TypeMessage.SUCCESS):
        print(f'{ColorTab.OKGREEN.value}[{i18n(TypeMessage.SUCCESS.value)}] - {msg} {ColorTab.ENDC.value}')
                   