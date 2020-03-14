

class DB:

    def __init__(self, setting=None):
        self.db_name = ''
        self.db_user = ''
        self.db_url_server = ''
        self.db_port = ''
        self.cursor = None
        self.connection = None
        self.last_query = ''
        self.status = 'no_connected'
        if setting is not None:
            self.connect(setting)

    def _set_attributes(self, setting=None):
        if setting is not None:
            self.db_name = setting["database"]
            self.db_user = setting["username"]
            self.db_url_server = setting["server"]
            self.db_port = setting["port"]
            self.status = 'connected'
        else:
            self.db_name = ''
            self.db_user = ''
            self.db_url_server = ''
            self.db_port = ''
            self.cursor = None
            self.connection = None
            self.last_query = ''
            self.status = 'no_connected'

    def connect(self, setting):
        try:
            self.connection = pyodbc.connect(f'DRIVER={setting["driver"]};' +
                                             f'SERVER={setting["server"]};' +
                                             f'DATABASE={setting["database"]};' +
                                             f'UID={setting["username"]};' +
                                             f'PWD={setting["password"]}'
                                             )
            print('DataBase connected\n')
            self.cursor = self.connection.cursor()
            self._set_attributes(setting)
        except Exception as ex:
            print('Connection to database error:\n', ex)

    def close_connection(self):
        self.connection.close()
        self._set_attributes()

    def execute(self, q=''):
        self.db.execute(q)
        self.db.commit()

    def insert(self, table, values, columns=None):
        if columns is None:
            columns = []
        try:
            columns = '(' + ','.join(map(str, columns)) + \
                ')' if columns else ''
            values = '(' + ','.join(map(str, columns)) + ')'
            values = f'(' + '","'.join(map(str, values)) + '")'
        except Exception as ex:
            print(ex)
            return
        sql = f"INSERT INTO {table} {columns} VALUES {values}"
        self.cursor.execute(sql)
        result = self.select(table, columns=["max(id) as id"]).fetchone()
        result = result[0] if result is not None else None
        return result

    def select(self, table, columns=[], where=None):
        try:
            columns = ','.join(map(str, columns)) if columns else '*'
        except Exception as ex:
            print(ex)
            return
        sql = f"SELECT {columns} FROM {table}"
        sql = sql + (f"WHERE {where}" if where is not None else '')
        print(sql)
        result = self.cursor.execute(sql)
        return result

    def sql_exec(self, sql=''):
        if sql:
            result = self.cursor.execute(sql)
            return result
        return None

    def create_table(self, columns, types=None):
        pass
