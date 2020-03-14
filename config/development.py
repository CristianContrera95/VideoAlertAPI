import os
import urllib


BASEDIR = os.path.abspath(os.path.dirname(__file__))
DEBUG = True
WTF_CSRF_ENABLED = True

DATABASE = {
    'driver': '{MySQL ODBC 8.0 Driver}',
    'server': '172.17.0.2',
    'port': '3306',
    'database': 'MineSecurity2',
    'username': 'root',
    'password': 'pidata20!',
}

params = urllib.parse.quote_plus(f'DRIVER={DATABASE["driver"]};' +
                                 f'SERVER={DATABASE["server"]};' +
                                 f'DATABASE={DATABASE["database"]};' +
                                 f'UID={DATABASE["username"]};' +
                                 f'PWD={DATABASE["password"]}')

SQLALCHEMY_ECHO = False
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_DATABASE_URI = f'mysql://{DATABASE["username"]}:{DATABASE["password"]}@{DATABASE["server"]}:{DATABASE["port"]}/{DATABASE["database"]}'
