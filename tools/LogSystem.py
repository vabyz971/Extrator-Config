
import os
import logging
from posixpath import dirname
from datetime import datetime


class LogSystem():

    def __init__(self):
        self.path = os.path.join('logs', 'log')

        date = str("{0}-{1}-{2}").format(datetime.now().month,
                                         datetime.now().day, 
                                         datetime.now().year)
        self.file = self.path + "_" + date + ".log"

    def ChangePathLog(self, _path):
        self.path = _path

    def CreateLog(self):
        logging.basicConfig(filename=self.file,
                            level=logging.INFO,
                            format='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.info("[EXTRACTION CONFIG LOG]")
