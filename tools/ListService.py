import psutil, logging


def list_service_linux():

    services = [(
        psutil.Process(p).name(),
        psutil.Process(p).status(),
        psutil.Process(p).create_time(),
    ) for p in psutil.pids()]

    for service in services:
        logging.info(
            "[SERVICE] name: "+ service[0] + 
            " / status: " + service[1])


def list_service_window():
    services = [psutil.win_service_iter()]

    for service in services:
        print(service)