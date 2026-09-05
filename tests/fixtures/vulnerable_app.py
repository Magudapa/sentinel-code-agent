import hashlib
import os
import subprocess


def get_user_order(user_id):
    # S004: SQL injection via f-string
    db = connect()
    cur = db.cursor()
    query = f"SELECT * FROM orders WHERE user_id = '{user_id}'"
    cur.execute(query)
    return cur.fetchall()

def auth(token):
    api_key = "sk-ABCD1234sk-ABCD1234sk-ABCD"  # S002 fake OpenAI key
    secret = "super_secret_password_123!"      # S001
    return hashlib.md5(token.encode()).hexdigest()  # S010 weak hash

def run(command):
    # S007 / S006: shell command execution
    os.system(command)
    subprocess.run(command, shell=True)

def load_data(path):
    # S008 unsafe pickle
    import pickle
    with open(path, "rb") as fh:
        return pickle.load(fh)

def parse(yaml_text):
    # S009 unsafe yaml.load
    import yaml
    return yaml.load(yaml_text)

def debug_server(host="0.0.0.0"):  # S013 broad binding
    app.debug = True  # S012
    app.run(host=host)

def handler(evt):
    eval(evt["payload"])  # S005 unsafe eval