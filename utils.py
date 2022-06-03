from logging.handlers import TimedRotatingFileHandler
import logging
from sys import platform
import sqlite3
import datetime

# Get Database file by SO
if platform == "win32":
    traps_db = 'c:/bin/traps_database.db'
else:
    traps_db = '/var/log/jenkins/project_csv_files/obtain_encryption_mode_status/traps_database.db'


# Function to save the trap to the database
def save_to_db_trap(traps=None):
    if traps is None:
        traps = {}
    conn = sqlite3.connect(traps_db)
    cursor = conn.cursor()

    timestamp_string = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S%z")

    for key, values in traps.items():
        for oid in values:
            params = (timestamp_string, key, oid[0], oid[1])

            cursor.execute(
                "INSERT INTO traps_catcher('date','ip','oid','value') VALUES(?,?,?,?)", params)
        print(".")
    conn.commit()
    conn.close()


def init_logging(logger, level, log_file=None):
    fmt = "%(asctime)s - %(pathname)s - %(funcName)s - %(lineno)d - %(levelname)s - %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)

    level = getattr(logging, level.upper())
    logger.setLevel(level)
    log_file = "logs/"+log_file
    if log_file:
        from logging.handlers import TimedRotatingFileHandler
        handler = TimedRotatingFileHandler(
            log_file, when="D", interval=1, backupCount=30)
    else:
        handler = logging.StreamHandler()

    handler.setLevel(level)
    handler.setFormatter(formatter)

    logger.addHandler(handler)
