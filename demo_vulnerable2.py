import os

def run_diagnostic(command):
    os.system("ping -c 1 " + command)

def fetch_all_records(db):
    return db.execute("SELECT * FROM transactions").fetchall()