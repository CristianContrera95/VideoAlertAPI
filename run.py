from flask import Flask, render_template
from flask_socketio import SocketIO
from api_resources import set_socket_obj, WebSocketAlert
from flask_cors import CORS


config = 'config.development'


def index():
    return render_template('index.html')


def create_app(config_filename):
    app = Flask(__name__)
    cors = CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
    app.config.from_object(config_filename)
    app.config['SQLALCHEMY_POOL_RECYCLE'] = 3600
    # TODO: sento all fix stringo to config.ini file
    app.config['SECRET_KEY'] = 'secret!'

    app.add_url_rule('/', 'index', index)

    from app import app_bp
    app.register_blueprint(app_bp, url_prefix='/api')

    from models import db
    db.init_app(app)

    # from utils import alert_event_handle
    # socketio.on_event('alert', alert_event_handle, namespace='/alert')

    return app


if __name__ == '__main__':
    app_ = create_app(config)

    socketio = SocketIO(app_)

    socketio.on_namespace(WebSocketAlert('/alert'))
    set_socket_obj(socketio)

    socketio.run(app_, host='0.0.0.0', port=5000)
