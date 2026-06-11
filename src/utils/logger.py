import logging
from PySide6.QtCore import QObject, Signal

class LogHandler(logging.Handler, QObject):
    log_signal = Signal(str, str) # message, level

    def __init__(self):
        logging.Handler.__init__(self)
        QObject.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        self.log_signal.emit(msg, record.levelname)

def setup_logger():
    logger = logging.getLogger("BahaaIT")
    logger.setLevel(logging.DEBUG)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    
    # UI handler
    ui_handler = LogHandler()
    ui_handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
    ch.setFormatter(formatter)
    ui_handler.setFormatter(formatter)
    
    logger.addHandler(ch)
    logger.addHandler(ui_handler)
    
    return logger, ui_handler
