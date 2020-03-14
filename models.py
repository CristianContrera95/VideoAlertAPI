from sqlalchemy import exc
from marshmallow import fields
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy

from utils import response
ma = Marshmallow()
db = SQLAlchemy()


MAX_INTEGER_MYSQL = 2147483647


def parse_sql_errors(error):
    pass


class ModelBase:

    def commit(self):
        try:
            db.session.commit()
            return self
        except:
            return False

    def save(self):
        try:
            db.session.add(self)
            db.session.commit()
        except exc.IntegrityError as ex:
            return response(409, f'Confict in Database: {ex.args[0].split(".")[4]}')
        except Exception as ex:
            return response(500, f'Data base error\n{ex}')


class Permission(ModelBase, db.Model):
    __tablename__ = 'permission'

    id = db.Column('id', db.Integer, autoincrement=True, primary_key=True)
    read_our_logs = db.Column('read_our_logs', db.Boolean, default=False)
    read_our_alerts = db.Column('read_our_alerts', db.Boolean, default=False)
    read_other_logs = db.Column('read_other_logs', db.Boolean, default=False)
    read_other_alerts = db.Column('read_other_alerts', db.Boolean, default=False)

    write_our_logs = db.Column('write_our_logs', db.Boolean, default=False)
    write_our_alerts = db.Column('write_our_alerts', db.Boolean, default=False)
    write_other_logs = db.Column('write_other_logs', db.Boolean, default=False)
    write_other_alerts = db.Column('write_other_alerts', db.Boolean, default=False)

    delete_our_logs = db.Column('delete_our_logs', db.Boolean, default=False)
    delete_our_alerts = db.Column('delete_our_alerts', db.Boolean, default=False)
    delete_other_logs = db.Column('delete_other_logs', db.Boolean, default=False)
    delete_other_alerts = db.Column('delete_other_alerts', db.Boolean, default=False)

    def __init__(self, **kwargs):
        for key in kwargs:
            if hasattr(self, key):
                setattr(self, key, kwargs[key])

    def __repr__(self):
        return f'permission {self.id}'


class Role(ModelBase, db.Model):
    __tablename__ = 'role'

    PERMISION = {'Admin': 1,
                 'Full': 2,
                 'Limited': 3,
                 'Unauthoried': 4
                 }

    id = db.Column('id', db.Integer, autoincrement=True, primary_key=True)
    permission_id = db.Column('permission_id', db.ForeignKey('permission.id', ondelete='CASCADE'), nullable=False)
    role_name = db.Column('role_name', db.String(25), default='Unauthorized')

    def __init__(self, role_name):
        if role_name == 'Admin':
            self.role_name = role_name
        elif role_name == 'Full':
            self.role_name = role_name
        elif role_name == 'Limited':
            self.role_name = role_name
        else:
            self.role_name = 'Unauthorized'
        self.permission_id = self.PERMISION[self.role_name]

    def __repr__(self):
        return f'{self.role_name} role'


class Account(ModelBase, db.Model):
    __tablename__ = 'account'

    id = db.Column('id', db.Integer, autoincrement=True, primary_key=True)
    # TODO: change role_id: nullable to False to allow roles and permissions
    role_id = db.Column('role_id', db.ForeignKey('role.id', ondelete='CASCADE'), nullable=True)
    password = db.Column('password', db.String(255), nullable=False)
    # secret = db.Column('secret', db.String(255), nullable=False)  # field to add unique secret for each account

    def __init__(self, password, role_id):
        super(Account, self).__init__()
        self.password = password
        self.role_id = role_id

    def __repr__(self):
        return f'Account {self.id}'


class User(ModelBase, db.Model):
    __tablename__ = 'user'

    id = db.Column('id', db.Integer, autoincrement=True, primary_key=True)
    account_id = db.Column('account_id', db.ForeignKey('account.id', ondelete='CASCADE'), nullable=False)
    username = db.Column('username', db.String(255), unique=True)
    last_update = db.Column('last_update', db.DateTime,server_default=db.func.current_timestamp(), nullable=True)
    email = db.Column('email', db.String(255), unique=True)
    # location

    def __init__(self, username, email):
        self.username = username
        self.email = email

    def __repr__(self):
        return f'user: {self.username}'


class Jetson(ModelBase, db.Model):
    __tablename__ = 'jetson'

    id = db.Column('id', db.Integer, autoincrement=True, primary_key=True)
    account_id = db.Column('account_id', db.ForeignKey('account.id', ondelete='CASCADE'), nullable=False)
    # TODO: Add status field to reuse the ip
    ip = db.Column('ip', db.String(16), nullable=False, unique=True)
    mac = db.Column('mac', db.String(255), nullable=False, unique=True)

    def __init__(self, ip, mac):
        self.mac = mac
        self.ip = ip

    def __repr__(self):
        return f'Device {self.mac}'


class Truck(ModelBase, db.Model):
    __tablename__ = 'truck'

    id = db.Column('id', db.Integer, autoincrement=True, primary_key=True)
    jetson_id = db.Column('jetson_id', db.ForeignKey('jetson.id', ondelete='CASCADE'), nullable=False)
    name = db.Column('name', db.String(255), nullable=False, unique=True)
    status = db.Column('status', db.String(20), default='Active')

    # account = db.relationship("Auth", back_populates="accounts")

    def __init__(self, name, account_id, status='Active'):
        super(Truck, self).__init__()
        self.name = name
        self.account_id = account_id
        self.status = status

    def __repr__(self):
        return f'Truck {self.name} is {self.status}'


class Alert(ModelBase, db.Model):
    __tablename__ = 'alert'

    id = db.Column('id', db.Integer, autoincrement=True, primary_key=True)
    truck_id = db.Column('truck_id', db.ForeignKey('truck.id', ondelete='CASCADE'), nullable=False)
    alert_init = db.Column('alert_init', db.DateTime, server_default=db.func.current_timestamp(), nullable=False)
    alert_end = db.Column('alert_end', db.DateTime, nullable=True)
    behavior = db.Column('behavior', db.String(255), default='Unknow', nullable=False)
    started = db.Column('started', db.Boolean, default=True)

    def __init__(self, truck_id, alert_init, behavior, started=True):
        super(Alert, self).__init__()
        self.truck_id = truck_id
        self.alert_init = alert_init
        self.behavior = behavior
        self.started = started

    def __repr__(self):
        return f'Alert {self.id}: Truck {self.truck_id} at {self.alert_init} <behavior: {self.behavior}>'


class Frame(ModelBase, db.Model):
    __tablename__ = 'frame'

    id = db.Column('id', db.Integer, autoincrement=True, primary_key=True, unique=True)
    alert_id = db.Column('alert_id', db.ForeignKey('alert.id', ondelete='CASCADE'), nullable=True)
    frame_timestamp = db.Column('frame_timestamp', db.DateTime, server_default=db.func.current_timestamp())
    frame_index = db.Column('frame_index', db.Integer)
    frame_image = db.Column('frame', db.LargeBinary)

    def __init__(self, alert_id, frame_timestamp,  frame_image, frame_index=0):
        super(Frame, self).__init__()
        self.alert_id = alert_id
        self.frame_timestamp = frame_timestamp
        self.frame_index = frame_index
        self.frame_image = frame_image

    def __repr__(self):
        return f'Frame {self.id}: {self.frame_index} at {self.frame_timestamp} from alert: {self.alert_id}'


class SafeFrame(ModelBase, db.Model):
    __tablename__ = 'safeframe'

    id = db.Column('id', db.Integer, autoincrement=True, primary_key=True, unique=True)
    truck_id = db.Column('truck_id', db.ForeignKey('truck.id', ondelete='CASCADE'), nullable=True)
    frame_timestamp = db.Column('frame_timestamp', db.DateTime, server_default=db.func.current_timestamp())
    frame_index = db.Column('frame_index', db.Integer)
    frame_image = db.Column('frame', db.LargeBinary)

    def __init__(self, truck_id, frame_timestamp,  frame_image, frame_index=0):
        super(SafeFrame, self).__init__()
        self.truck_id = truck_id
        self.frame_timestamp = frame_timestamp
        self.frame_index = frame_index
        self.frame_image = frame_image

    def __repr__(self):
        return f'SafeFrame {self.id}: {self.frame_index} at {self.frame_timestamp} from truck: {self.truck_id}'


class PermissionSchema(ma.Schema):
    id = fields.Integer()
    read_our_logs = fields.String()
    read_our_alerts = fields.String()
    read_other_logs = fields.String()
    read_other_alerts = fields.String()

    write_our_logs = fields.String()
    write_our_alerts = fields.String()
    write_other_logs = fields.String()
    write_other_alerts = fields.String()

    delete_our_logs = fields.String()
    delete_our_alerts = fields.String()
    delete_other_logs = fields.String()
    delete_other_alerts = fields.String()


class RoleSchema(ma.Schema):
    id = fields.Integer()
    permission_id = fields.Integer()
    role_name = fields.Integer()


class AccountSchema(ma.Schema):
    id = fields.Integer()
    role_id = fields.Integer()
    password = fields.String(required=True)
    # secret = fields.String()


class JetsonSchema(ma.Schema):
    id = fields.Integer()
    account_id = fields.Integer()
    ip = fields.String(required=True)
    mac = fields.String(required=True)


class UserSchema(ma.Schema):
    id = fields.Integer()
    account_id = fields.Integer()
    username = fields.String(required=True)
    email = fields.String()


class TruckSchema(ma.Schema):
    id = fields.Integer()
    name = fields.String(required=True)
    account_id = fields.Integer()
    status = fields.String()


class AlertSchema(ma.Schema):
    id = fields.Integer()
    truck_id = fields.Integer()
    alert_init = fields.DateTime()
    alert_end = fields.DateTime()
    behavior = fields.String(required=True)
    started = fields.Boolean()


class FrameSchema(ma.Schema):
    id = fields.Integer()
    alert_id = fields.Integer()
    frame_timestamp = fields.DateTime(required=True)
    frame_index = fields.Integer()
    frame_image = fields.String()


class SafeFrameSchema(ma.Schema):
    id = fields.Integer()
    truck_id = fields.Integer()
    frame_timestamp = fields.DateTime(required=True)
    frame_index = fields.Integer()
    frame_image = fields.String()
