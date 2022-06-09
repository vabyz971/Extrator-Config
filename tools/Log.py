import os
import time
import datetime
from .libCreate import read_os_releases
  

os_release = dict(read_os_releases())
linux = os.path.join("Logs",os_release.get('ID')+"_"+os_release.get('VERSION_ID'))

def CreateLogFile():
    if(os.path.exists(linux)):
        pass
    else:
        os.makedirs(linux)
    

def AddLineLog(msg:str):
    CreateLogFile()
    if(os.path.exists(linux)):
        log = open(os.path.join(linux, f"log_{datetime.date.today()}.txt"), "a")
        if(msg):
            log.write("["+time.asctime(time.localtime(time.time()) ) +"] : "+ msg+ '\n')
        else:
            pass
        log.close()
