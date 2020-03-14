import os
import re
from datetime import datetime as dt
from subprocess import call
from base64 import b64decode, b64encode
from sqlalchemy import text

import requests
import marshmallow
from flask import request
from flask_restful import Resource
from flask_socketio import Namespace, emit

import math

from models import (Permission, PermissionSchema,
                    Role, RoleSchema,
                    Account, AccountSchema,
                    User, UserSchema,
                    Jetson, JetsonSchema,
                    Truck, TruckSchema,
                    Alert, AlertSchema,
                    Frame, FrameSchema,
                    SafeFrame, SafeFrameSchema,
                    )

from utils import (response,
                   get_data,
                   hash_password,
                   gen_token,
                   decode_token,
                   validate_token,
                   validate_date,
                   validate_mac_format,
                   validate_ip_format,
                   validate_mail_format,
                   validate_ip_up,
                   validate_json_payload,
                   alert_event_notify,
                   BEHAVIORS)

users_connected = {}
socket_obj = None

check_frontend_auth = True


def set_socket_obj(app_):
    global socket_obj
    socket_obj = app_


class Base(Resource):

    def __init__(self):
        super(Base, self).__init__()

    @staticmethod
    def _validate_data(username=None, role_name=None, mac=None, ip=None, password=None, name=None, truck_id=None, alert_id=None,
                       behavior=None, date_=None, email=None):
        if password and len(password) >= 255:
            return response(413, 'Password is too large.')

        if mac and not validate_mac_format(mac):
            return response(400, 'Mac doesn\'t has correct format.')

        if ip and not validate_ip_format(ip):
            return response(400, 'Ip doesn\'t has correct format.')

        if ip and not validate_ip_up(ip):
            return response(400, 'Ip couldn\'t be research.')

        if email and not validate_mail_format(email):
            return response(400, 'Email doesn\'t has correct format.')

        if username and User.query.filter_by(username=username).first():
            return response(409, 'Username already register.')

        if name and Truck.query.filter_by(name=name).first():
            return response(409, 'Truck already register.')

        if role_name and not Role.query.filter_by(role_name=role_name).first():
            return response(409, 'Role doesn\'t exists.')

        if truck_id and not Truck.query.filter_by(id=truck_id).first():
            return response(400, 'Truck_id doesn\'t exists.')

        if alert_id and not Alert.query.filter_by(id=alert_id, started=True).first():
            return response(400, 'Alert_id doesn\'t exists or is close.')

        if behavior and behavior not in BEHAVIORS:
            return response(400, 'Behavior Unknow.')

        if date_ and not validate_date(date_):
            return response(400, 'date fields must be in \'%Y-%m-%d %H:%M:%S\' format.')

    def _validate_user(self, username):
        return True if User.query.filter_by(username=username).first() else False

    def _validate_truck(self, name):
        return True if Truck.query.filter_by(name=name).first() else False

    def validate_jetson_data(self, device_data, data_dict=None):
        token_data = decode_token(device_data['token'])

        jetson = Jetson.query.filter_by(mac=token_data['mac']).first()
        truck = Truck.query.filter_by(id=device_data['truck_id']).first()

        if truck.jetson_id != jetson.id:
            return response(400, 'Wrong token')

        if data_dict:
            error = self._validate_data(**data_dict)
            if error:
                return error

    def get_usertoken_data(self, token):

        token_data = decode_token(token)
        if not token_data:
            return None, response(400, 'Wrong token')

        if not self._validate_user(token_data['username']):
            return None, response(400, 'User doesn\'t exists')
        return token_data, None

    def get_pages_data(self, data, page, limit=None):
        limit = self.per_page if limit is None else int(limit)
        total_pages = math.ceil(data.count() / limit)
        total_items = data.count()
        alerts = data.paginate(page, limit, False).items
        return total_pages, total_items, limit, alerts

    def get(self):
        return response(401)

    def post(self):
        return response(401)

    def put(self):
        return response(401)

    def delete(self):
        return response(401)


class PermissionResource(Base):
    def __init__(self):
        super(PermissionResource, self).__init__()
        self.permission_schema = PermissionSchema()
        self.permissions_schema = PermissionSchema(many=True)


class RoleResource(Base):
    def __init__(self):
        super(RoleResource, self).__init__()
        self.role_schema = RoleSchema()
        self.roles_schema = RoleSchema(many=True)


class AccountResource:

    def __init__(self):
        super(AccountResource, self).__init__()
        self.account_schema = AccountSchema()
        self.accounts_schema = AccountSchema(many=True)


class UserResource(Base, AccountResource):

    def __init__(self):
        super(UserResource, self).__init__()
        self.user_schema = UserSchema()
        self.users_schema = UserSchema(many=True)
        self.per_page = 20  # TODO:  move fix num to config file
        self.fields = [('username', True), ('password', True), ('email', True), ('role', True)]
        self.token_data = ['username', 'password']

    def validate_permission(self, user, action):
        username = user['username']
        users = User.query
        user = User.query.filter_by(username=username).first()
        if user:
            return True
            # account = Account.query.filter_by(id=user.account_id).first()
            #
            # TODO: validate_token and below:
            #
            # role = Role.query.filter_by(id=account.role_id).first()
            #
            # if role.role_name == action:
            #     return True
        return False

    def get(self):
        """
        Get a list of users filterd by ( id, username, email, sort_name, sort_order, limit, role_name )
        """
        _, error = self.get_usertoken_data(request.args.get('token', ''))
        if not error:

            user_id = int(request.args.get('user_id', 0))
            username = request.args.get('username', '')
            email = request.args.get('email', '')
            sort_name = request.args.get('sort_name', '')  # column name to filter
            sort_order = request.args.get('sort_order', '')  # asc | desc
            limit = request.args.get('limit', None)
            role_name = request.args.get('role', '')

            users = User.query.join(Account, Account.id == User.account_id).join(Role, Role.id == Account.role_id)
            if users and user_id:
                users = users.filter_by(id=user_id)
            elif users and email:
                users = users.filter_by(email=email)
            elif users and username:
                 users = users.filter_by(username=username)
            else:
                if users and role_name:
                    users = users.filter(Role.role_name == role_name)
                if users and sort_name:
                    users = users.order_by(text(f'user.{sort_name} {sort_order}'))
                else:
                    users = users.order_by(User.id.desc())

            total_pages, total_items, limit, users = self.get_pages_data(users,
                                                                         int(request.args.get('page', 1)),
                                                                         limit)
            result = self.users_schema.dump(users)
            for user in result:
                account = Account.query.filter_by(id=user['account_id']).first()
                role = Role.query.filter_by(id=account.role_id).first()
                user['role'] = role.role_name
            return response(200, data={'users': result,
                                       'totalPages': total_pages,
                                       'totalItems': total_items,
                                       'perPage': limit})
        return error

    def post(self):
        """
        Register a new user if curr_user has permission
        :param requests: {token: curr_user_token    , new_user:{username, password, email, role}}
        :return: {id, json web token}
        """
        json_data, error = get_data(request)
        if not error:
            data, error = validate_json_payload(json_data, [('token', True), ('new_user', True)])
            if not error:
                token_data, error = self.get_usertoken_data(data['token'])
                curr_user = token_data['username']

                _, error = validate_json_payload(data['new_user'], self.fields)
                if not error:
                    new_user = data['new_user']
                    del token_data, data

                    if self.validate_permission(curr_user, 'create_new_user'):
                        error = self._validate_data(username=new_user['username'],
                                                    password=new_user['password'],
                                                    email=new_user['email'],
                                                    role_name=new_user['role'])
                        if not error:
                            new_user['password'] = hash_password(new_user['password'])
                            token = gen_token({key: new_user[key] for key in self.token_data})

                            try:
                                role = Role.query.filter_by(role_name=new_user['role']).first()
                                account_data = self.account_schema.load({'password': new_user['password'],
                                                                         'role_id': role.id})
                                user_data = self.user_schema.load({'username': new_user['username'],
                                                                   'email': new_user['email']})
                            except marshmallow.exceptions.ValidationError as errors:
                                return response(400, str(errors))

                            new_account = Account(**account_data)
                            new_user = User(**user_data)

                            error = new_account.save()
                            if not error:
                                new_user.account_id = new_account.id
                                error = new_user.save()
                                if not error:
                                    return response(200, data={'id': new_user.id,
                                                               'token': token})
                    else:
                        return response(400, 'Current user don\'t has permission')
        return error

    def put(self):
        """
        Update data to new user and return new token
        :return: {id, json web token}
        """
        json_data, error = get_data(request)
        if not error:
            data, error = validate_json_payload(json_data, [('token', True), ('new_user', True)])
            if not error:

                curr_user, error = self.get_usertoken_data(data['token'])

                # curr_user = token_data['username']

                _, error = validate_json_payload(data['new_user'],
                                                 [('username', True)] + [(field, False) for field, _ in self.fields[1:]])
                if not error:
                    update_user = data['new_user']
                    del data

                    if self.validate_permission(curr_user, 'update_new_user'):
                        if self._validate_user(update_user['username']):
                            error = self._validate_data(
                                password=update_user['password'] if 'password' in update_user.keys() else None,
                                email=update_user['email'] if 'email' in update_user.keys() else None,
                                role_name=update_user['role'] if 'role' in update_user.keys() else None)

                            if not error:
                                if 'password' in update_user.keys():
                                    update_user['password'] = hash_password(update_user['password'])

                                token = gen_token({key: update_user[key] for key in self.token_data})

                                user = User.query.filter_by(username=update_user['username']).first()
                                account = Account.query.filter_by(id=user.account_id).first()

                                if 'email' in update_user.keys():
                                    user.email = update_user['email']
                                user.last_update = dt.now().strftime('%Y-%m-%d %H:%M:%S')
                                error = user.save()
                                if not error:
                                    if 'role' in update_user.keys():
                                        role = Role.query.filter_by(role_name=update_user['role']).first()
                                        account.role_id = role.id
                                    if 'password' in update_user.keys():
                                        account.password = update_user['password']
                                    error = account.save()
                                    if not error:
                                        return response(200, data={'id': account.id,
                                                                   'token': token})
                    else:
                        return response(400, 'Current user don\'t has permission')
        return error


class LoginResource(Base):
    def __init__(self):
        super(LoginResource, self).__init__()

    def post(self):
        # @TODO: Implement PiConsulting: Needs to authenticate OAUTH
        json_data, error = get_data(request)
        if not error:
            username = json_data['username']
            user = User.query.filter_by(username=username).first()
            # @TODO: Validate password

            account = Account.query.filter_by(id=user.account_id).first()
            json_data['password'] = hash_password(json_data['password'])
            token = gen_token(json_data)

        return response(200, data={'token': token})


class LogoutResource(Base):
    def __init__(self):
        super(LogoutResource, self).__init__()

    def get(self):
        # @TODO: Implement PiConsulting
        return response(200)


class TruckResource(Base):

    def __init__(self):
        super(TruckResource, self).__init__()
        self.truck_schema = TruckSchema()
        self.trucks_schema = TruckSchema(many=True)
        self.per_page = 10

    def get(self):
        _, error = self.get_usertoken_data(request.args.get('token', ''))
        if not error:

            truck_id = request.args.get('id', '')
            name = request.args.get('name', '')
            status = request.args.get('status', 'Active')
            sort_name = request.args.get('sort_name', '')  # column name to filter
            sort_order = request.args.get('sort_order', '')  # asc | desc
            limit = request.args.get('limit', None)
            include_last_alert = request.args.get('include_last_alert', '')
            last_alert_time_start = request.args.get('last_alert_time_start', '')
            last_alert_time_end = request.args.get('last_alert_time_end', '')

            trucks = Truck.query
            if trucks and truck_id:
                trucks = trucks.filter_by(truck_id=truck_id)
            elif trucks and name:
                trucks = trucks.filter_by(name=name)
            else:
                if trucks and status:
                    trucks = trucks.filter_by(status=status)
                if trucks and sort_name:
                    trucks = trucks.order_by(text(f'truck.{sort_name} {sort_order}'))
                else:
                    trucks = trucks.order_by(Truck.id.desc())
                if trucks and last_alert_time_start and last_alert_time_end:
                    alerts = Alert.query.filter(Alert.alert_init >= last_alert_time_start,
                                                Alert.alert_end <= last_alert_time_end)
                    trucks = trucks.filter(Truck.id.in_([alert.truck_id for alert in alerts]))

            total_pages, total_items, limit, trucks = self.get_pages_data(trucks,
                                                                          int(request.args.get('page', 1)),
                                                                          limit)

            result = self.trucks_schema.dump(trucks)

            if include_last_alert:
                for truck in result:
                    alerts = Alert.query.filter_by(truck_id=truck['id'])

                    alert = alerts.order_by(Alert.id.desc()).first()
                    alerts_total = alerts.count()
                    alert_init = alert.alert_init.strftime('%Y-%m-%d %H:%M:%S')
                    alert_end = alert.alert_end.strftime('%Y-%m-%d %H:%M:%S') if alert.alert_end is not None else ''
                    truck['alerts_total'] = alerts_total
                    truck['last_alert'] = {'id': alert.id,
                                           'alert_init': alert_init,
                                           'alert_end': alert_end,
                                           'behavior': alert.behavior,
                                           'started': alert.started}

            return response(200, data={'trucks': result,
                                       'totalPages': total_pages,
                                       'totalItems': total_items,
                                       'perPage': limit})
        return error


class JetsonResource(AccountResource, TruckResource):

    def __init__(self):
        super(JetsonResource, self).__init__()
        self.jetson_schema = JetsonSchema()
        self.jetsons_schema = JetsonSchema(many=True)
        self.fields = [('mac', True), ('password', True), ('name', True), ('role', False)]
        self.token_data = ['mac', 'ip', 'password']

    def post(self):
        """
        Register a new jetson device
        :return: {id, json web token}
        """
        json_data, error = get_data(request)
        if not error:
            device_data, error = validate_json_payload(json_data, self.fields)
            device_data['ip'] = request.remote_addr  # TODO: que pasa si el ip ya existe en otro jetson?
            if not error:
                error = self._validate_data(mac=device_data['mac'],
                                            ip=device_data['ip'],
                                            password=device_data['password'],
                                            name=device_data['name'],
                                            role_name=device_data['role'] if 'role' in device_data.keys() else None)
                if not error:
                    device_data['password'] = hash_password(device_data['password'])
                    token = gen_token({key: device_data[key] for key in self.token_data})

                    try:
                        role = Role.query.filter_by(
                            role_name=device_data['role'] if 'role' in device_data.keys() else 'Limited'
                        ).first()
                        account_data = self.account_schema.load({'password': device_data['password'],
                                                                 'role_id': role.id})
                        jetson_data = self.jetson_schema.load({'ip': device_data['ip'], 'mac': device_data['mac']})
                        truck_data = self.truck_schema.load({'name': device_data['name']})

                    except marshmallow.exceptions.ValidationError as errors:
                        return response(400, str(errors))

                    account = Account(**account_data)

                    error = account.save()
                    if not error:
                        jetson = Jetson(**jetson_data)
                        jetson.account_id = account.id
                        error = jetson.save()
                        if not error:
                            truck = Truck(**truck_data, account_id=account.id)
                            truck.jetson_id = jetson.id
                            error = truck.save()
                            if not error:
                                return response(200, data={'id': account.id,
                                                           'truck_id': truck.id,
                                                           'token': token})
        return error

    def put(self):
        """
        Update ip and get new token
        :return: {id, json web token}
        """
        json_data, error = get_data(request)
        if not error:
            device_data, error = validate_json_payload(json_data, self.fields)
            device_data['ip'] = request.remote_addr
            if not error:
                error = self._validate_data(mac=device_data['mac'],
                                            ip=device_data['ip'],
                                            password=device_data['password'],
                                            role_name=device_data['role'] if 'role' in device_data.keys() else None)
                if not error:
                    device_data['password'] = hash_password(device_data['password'])
                    token = gen_token({key: device_data[key] for key in self.token_data})
                    try:
                        role = Role.query.filter_by(
                            role_name=device_data['role'] if 'role' in device_data.keys() else 'Limited'
                        ).first()
                        jetson = Jetson.query.filter_by(mac=device_data['mac']).first()
                        account = Account.query.filter_by(id=jetson.account_id).first()
                        truck = Truck.query.filter_by(jetson_id=jetson.id).first()
                    except:
                        return response(401, 'Jetson device dosen\'t exists')

                    if jetson.ip != device_data['ip']:
                        jetson.ip = device_data['ip']+'3'
                        error = jetson.save()
                        if error:
                            return response(500, 'Internal error')

                    if role.id != account.role_id:
                        account.role_id = role.id
                    error = account.save()

                    if not error:
                        return response(200, data={'id': account.id,
                                                   'truck_id': truck.id,
                                                   'token': token})
        return error


class AlertResource(Base):

    def __init__(self, app_context=None):
        super(AlertResource, self).__init__()
        self.alert_schema = AlertSchema()
        self.alerts_schema = AlertSchema(many=True)
        self.fields = [('token', True), ('truck_id', True),
                       ('alert_init', True), ('behavior', True)]
        self.per_page = 20
        # self.app_context = app_context

    def get(self):
        _, error = self.get_usertoken_data(request.args.get('token', ''))
        if not error:

            truck_id = int(request.args.get('truck_id', 0))
            alert_id = int(request.args.get('id', 0))
            behavior = request.args.get('behavior', '')
            alert_init = request.args.get('alert_init', '')
            started = request.args.get('started', '')
            limit = request.args.get('limit', None)
            sort_name = request.args.get('sort_name', '')
            sort_order = request.args.get('sort_order', '')

            truck_name = request.args.get('truck_name', '')
            alert_init_start = request.args.get('alert_init_start', '')
            alert_init_end = request.args.get('alert_init_end', '')
            alert_finish_time_start = request.args.get('alert_finish_time_start', '')
            alert_finish_time_end = request.args.get('alert_finish_time_end', '')

            alerts = Alert.query

            # Si se recibe id no deberia recibir los demas filtros (Se ignoran por el momento)
            if alerts and alert_id:
                alerts = alerts.filter_by(id=alert_id)
            else:
                if alerts and truck_id:
                    alerts = alerts.filter_by(truck_id=truck_id)
                elif alerts and truck_name:
                    alerts = alerts.join(Truck, Alert.id == Truck.id).filter(Truck.name == truck_name)
                if alerts and behavior:
                    alerts = alerts.filter_by(behavior=behavior)
                if alerts and alert_init:
                    alerts = alerts.filter(Alert.alert_init >= alert_init)
                elif alerts and alert_init_start and alert_init_end:
                    alerts = alerts.filter(Alert.alert_init >= alert_init_start,
                                           Alert.alert_init <= alert_init_end)
                if alerts and alert_finish_time_start and alert_finish_time_end:
                    alerts = alerts.filter(Alert.alert_end >= alert_finish_time_start,
                                           Alert.alert_end <= alert_finish_time_end)
                if alerts and started:
                    alerts = alerts.filter_by(started=started)
                if alerts and sort_name:
                    alerts = alerts.order_by(text(f'alert.{sort_name} {sort_order}' ))

            total_pages, total_items, limit, alerts = self.get_pages_data(alerts,
                                                                          int(request.args.get('page', 1)),
                                                                          limit)
            result = self.alerts_schema.dump(alerts)
            return response(200, data={'alerts': result,
                                       'totalPages': total_pages,
                                       'totalItems': total_items,
                                       'perPage': limit})
        return error

    def post(self):
        """
        Create a new alert
        """
        global users_connected
        json_data, error = get_data(request)
        if not error:
            device_data, error = validate_json_payload(json_data, self.fields)
            if not error:
                error = self.validate_jetson_data(device_data,
                                                  data_dict={'truck_id': device_data['truck_id'],
                                                             'behavior': device_data['behavior'],
                                                             'date_': device_data['alert_init']})
                if not error:

                    try:
                        alert_data = self.alert_schema.load({'truck_id': device_data['truck_id'],
                                                             'behavior': device_data['behavior'],
                                                             'alert_init': device_data['alert_init']
                                                             })
                    except marshmallow.exceptions.ValidationError as errors:
                        return response(400, str(errors))

                    alert = Alert(**alert_data)
                    error = alert.save()
                    if not error:
                        # TODO: add alert.id to msg
                        alert_event_notify(socket_obj, users_connected)
                        return response(200, data={'alert_id': alert.id})
        return error

    def put(self):
        """
        Update an alert to close it
        """
        json_data, error = get_data(request)
        if not error:
            device_data, error = validate_json_payload(json_data, [('token', True), ('alert_id', True), ('alert_end', True)])
            if not error:
                error = self.validate_jetson_data(device_data,
                                                  data_dict={'alert_id': device_data['alert_id'],
                                                             'date_': device_data['alert_end']})
                if not error:
                    try:
                        alert = Alert.query.get(device_data['alert_id'])
                    except:
                        return response(400, 'Alert_id doesn\'t exists')

                    if not error:
                        alert.alert_end = device_data['alert_end']
                        alert.started = False
                        error = alert.save()
                        if not error:
                            return response(200, data={'id': alert.id})
        return error


class FrameResource(Base):

    def __init__(self):
        super(FrameResource, self).__init__()
        self.frame_schema = FrameSchema()
        self.frames_schema = FrameSchema(many=True)
        self.fields = [('token', True), ('alert_id', True),
                       ('frame_timestamp', True), ('frame', True)]
        self.per_page = 5

    def get(self):
        _, error = self.get_usertoken_data(request.args.get('token', ''))
        if not error:
            alert_id = int(request.args.get('alert_id', 1))

            frame_timestamp = request.args.get('frame_timestamp', None)
            frame_index = int(request.args.get('frame_index', 0))

            frames = Frame.query.filter_by(alert_id=alert_id).order_by(Frame.id.desc())
            if frames and frame_timestamp:
                frames = frames.filter(Frame.frame_timestamp >= frame_timestamp)
            if frames and frame_index:
                frames = frames.filter(Frame.frame_index >= frame_index)

            page = int(request.args.get('page', 1))
            frames = frames.paginate(page, self.per_page, False).items
            # TODO: add frame_total, per_page ( see alert.get() )
            result = self.frames_schema.dump(frames)
            count = 0
            for frame in frames:
                result[count]['frame'] = frame.frame_image.decode('utf-8')
                del result[count]['frame_image']
                count += 1
            return response(200, data={'frames': result})
        return error

    def post(self):
        """
        Save a frame
        """
        json_data, error = get_data(request)
        if not error:
            device_data, error = validate_json_payload(json_data, self.fields)
            if not error:
                error = self.validate_jetson_data(device_data,
                                                  data_dict={'alert_id': device_data['alert_id'],
                                                             'date_': device_data['frame_timestamp']})
                if not error:

                    try:
                        frame_data = self.frame_schema.load({'alert_id': device_data['alert_id'],
                                                             'frame_timestamp': device_data['frame_timestamp'],
                                                             'frame_index': device_data.get('frame_index', 0)
                                                             })
                    except marshmallow.exceptions.ValidationError as errors:
                        return response(400, str(errors))

                    frame = Frame(**frame_data, frame_image=bytes(device_data['frame'], 'utf-8'))
                    error = frame.save()
                    if not error:
                        return response(200, data={'frame_id': frame.id})
        return error


class SafeFrameResource(Base):

    def __init__(self):
        super(SafeFrameResource, self).__init__()
        self.safeframe_schema = SafeFrameSchema()
        self.safeframes_schema = SafeFrameSchema(many=True)
        self.fields = [('token', True), ('truck_id', True),
                       ('frame_timestamp', True), ('frame', True)]
        self.per_page = 5

    def post(self):
        json_data, error = get_data(request)
        if not error:
            device_data, error = validate_json_payload(json_data, self.fields)
            if not error:
                error = self.validate_jetson_data(device_data,
                                                  data_dict={'truck_id': device_data['truck_id'],
                                                             'date_': device_data['frame_timestamp']})
                if not error:
                    try:
                        safeframe_data = self.safeframe_schema.load({'truck_id': device_data['truck_id'],
                                                                     'frame_timestamp': device_data['frame_timestamp'],
                                                                     'frame_index': device_data.get('frame_index', 0)
                                                                     })
                    except marshmallow.exceptions.ValidationError as errors:
                        return response(400, str(errors))

                    safeframe = SafeFrame(**safeframe_data, frame_image=bytes(str(device_data['frame'])[2:-1], 'utf-8'))
                    error = safeframe.save()
                    if not error:
                        return response(200, data={'safeframe_id': safeframe.id})
        return error


class JetsonLastStatusResourse(Base):

    def __init__(self):
        super(JetsonLastStatusResourse, self).__init__()
        self.safeframe_schema = SafeFrameSchema()
        self.frame_schema = FrameSchema()

    def get(self):
        truck_id = int(request.args.get('truck_id', 1))

        token_data, error = self.get_usertoken_data(request.args.get('token', ''))
        if not error:
            alerts = Alert.query.filter_by(truck_id=truck_id)
            alerts_idx = [alert.id for alert in alerts]
            safeframe = SafeFrame.query.filter_by(truck_id=truck_id).order_by(SafeFrame.id.desc()).first()
            frame = Frame.query.filter(Alert.id.in_(alerts_idx)).order_by(Frame.id.desc()).first()
            if safeframe.frame_timestamp >= frame.frame_timestamp:
                result = self.safeframe_schema.dump(safeframe)
            else:
                result = self.frame_schema.dump(frame)
            return response(200, data={'frame': result})
        return error


class JetsonCurrStatusResourse(Base):

    def __init__(self):
        super(JetsonCurrStatusResourse, self).__init__()

    def get(self):
        # TODO: Arreglar lo de abajo, no anda
        # token = request.args.get('token', '')
        # username = request.args.get('username', '')
        # truck_id = int(request.args.get('truck_id', 0))
        # print(username, self._validate_user(username))

        # if not self._validate_user(username):
        #     return response(400, 'User doesn\'t exists')
        # if not truck_id:
        #     return response(400, 'Truck doesn\'t exists')

        # user = User.query.filter_by(username=username).first()
        # account = Account.query.filter_by(id=user.account_id).first()
        # jetson = Jetson.query.filter_by(account_id=account.id).first()

        # token_data = decode_token(token)
        # if not token_data:
        #     return response(400, 'Wrong token')
        # error = validate_token(token_data, data={'username': user.username,
        #                                          'password': account.password,
        #                                          })
        # if not error:
        #     port = 8080
        # return error
        return response(200, data={
            "deviceId": 'botia-jetson-nano',
            "lastAlert": 'Unsafe',
            "lastAlertTimestamp": '2020-02-12 10:05:59',
            "lastFrameStatus": {
                "behavior": 'Unsafe',
                "frame": "fake_frame",
                "timestamp": '2020-02-12 10:05:59'
            },
            "startTime": '2020-02-12 09:54:19'
        })


class WebSocketAlert(Namespace, Base):

    def on_connect(self):
        print(f'{request.sid} connected')

    #        emit('my_response', {'data': 'Connected'})

    # def on_disconnect(self):
    #     global users_connected
    #     json_data, error = get_data(request)
    #     if not error:
    #         data, error = validate_json_payload(json_data, [('username', True), ('token', True)])
    #         if not error:
    #             del users_connected[data['username']]
    #     self.on_disconnect()

    def on_get_alert(self, data):
        global users_connected
        data, error = validate_json_payload(data, [('username', True), ('token', True)])
        if not error:
            token_data, error = self.get_usertoken_data(data['token'])
            if not error:
                try:
                    user = User.query.filter_by(username=data['username']).first()
                except:
                    return response(400, 'Username doesn\'t exists')

                users_connected[user.username] = request.sid
                return emit('my_response', {'data': 'Added!'})
