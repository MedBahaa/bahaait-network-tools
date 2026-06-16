import logging
import os
from logging.handlers import RotatingFileHandler
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
    
    # File handler with rotation (Max 5MB, keep 3 backup files)
    try:
        app_data = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
        log_dir = os.path.join(app_data, 'BahaaIT', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, 'app.log')
        
        fh = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(file_formatter)
        logger.addHandler(fh)
    except Exception as e:
        print(f"Failed to setup file log handler: {e}")
    
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
    ch.setFormatter(formatter)
    ui_handler.setFormatter(formatter)
    
    logger.addHandler(ch)
    logger.addHandler(ui_handler)
    
    return logger, ui_handler
