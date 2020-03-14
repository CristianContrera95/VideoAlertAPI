import os
import re

from subprocess import call
from datetime import datetime as dt
from hashlib import pbkdf2_hmac

from flask_socketio import SocketIO, emit
import jwt

STATUS = {200: 'Success',
          201: 'Created',
          204: 'No Content',
          301: 'Moved Permanently',
          400: 'Bad Requests',
          401: 'Unauthorized',
          404: 'Not found',
          409: 'Conflict',
          413: 'Payload Too Large',
          500: 'Internal error'
          }

BEHAVIORS = ['Safe', 'Unsafe', "Eating/Drinking", "Single Hand", "Tamper"]


JWT_SECRET_KEY = os.environ.get('jwt', 'PiData20!.MineApi.Peru')
JWT_ALGORITHM = 'HS256'
JWT_NOISE = b'salt'


sockets = {}


def response(status_code, msg='', data=None):
    res = {'code': status_code, 'status_code': STATUS[status_code]}
    if msg:
        res.update({'error': msg})
    if data is not None:
        res.update({'data': data})

    return res, status_code


def get_data(request):
    try:
        json_data = request.get_json(force=True)
    except:
        json_data = None
    if not json_data:
        return None, response(400, 'No input data provided')
    return json_data, None


def hash_password(password):
    password_hash = pbkdf2_hmac('sha256', bytes(password, "utf-8"), JWT_NOISE, 10000)
    return password_hash.hex()


def gen_token(data):
    encoded_content = jwt.encode(data, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    token = str(encoded_content).split("'")[1]
    return token


def decode_token(token):
    try:
        data = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except Exception as e:
        print(e)
        data = None
    return data


def validate_token(token_data, data):
    for key in data.keys():
        if key in token_data.keys():
            if token_data[key] != data[key]:
                return response(400, 'Wrong token')
    return None


def validate_date(date_time):
    try:
        dt.strptime(date_time, '%Y-%m-%d %H:%M:%S')
        return True
    except:
        return False


def validate_mac_format(mac):
    return True if re.fullmatch('^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac) is not None else False


def validate_ip_format(ip):
    return True if re.fullmatch('^([0-9]{1,3}\.){3}([0-9]{1,3})$', ip) is not None else False


def validate_mail_format(email):
    return True


def validate_ip_up(ip):
    try:
        if call(['ping', '-c', '1', '-W', '3', '0.0.0.0']):
            return False
    except:
        return False
    return True


def validate_json_payload(json_data, fileds):
    field = None
    try:
        for (field, required) in fileds:
            if not (json_data[field] or required):
                json_data[field] = None
            elif (not json_data[field]) and required:
                return json_data, response(400, f'Missing value for "{field}" field in payload')
        return json_data, None
    except KeyError:
        return json_data, response(400, f'Missing "{field}" field in payload')


# async def notify_an_alert(socket, msg=None):
#     pass


def alert_event_handle(data):
    global sockets
    if isinstance(data, dict):
        if 'username' in data.keys():
            sockets[data['username']] = True


def alert_event_notify(socket_, users):
    for key, user_id in users.items():
        socket_.emit('an_alert', {'data': 'new_alert'}, room=user_id, namespace='/alert')
