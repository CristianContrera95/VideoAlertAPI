import os
import urllib


BASEDIR = os.path.abspath(os.path.dirname(__file__))
DEBUG = False
WTF_CSRF_ENABLED = True

DATABASE = {
    'driver': '{ODBC Driver 17 for SQL Server}',
    'server': 'tcp:pidb3.database.windows.net',
    'port': '1433',
    'database': 'MineSecurity2',
    'username': 'stingySmelt9',
    'password': 'pidata20!',
}


params = urllib.parse.quote_plus(f'DRIVER={DATABASE["driver"]};' +
                                 f'SERVER={DATABASE["server"]};' +
                                 f'DATABASE={DATABASE["database"]};' +
                                 f'UID={DATABASE["username"]};' +
                                 f'PWD={DATABASE["password"]}')

SQLALCHEMY_ECHO = False
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_DATABASE_URI = "mssql+pyodbc:///?odbc_connect=%s" % params
