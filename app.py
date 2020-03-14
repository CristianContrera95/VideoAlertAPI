from flask import Blueprint
from flask_restful import Api

from api_resources import (UserResource, JetsonResource, AlertResource, TruckResource,
                           FrameResource, SafeFrameResource, JetsonLastStatusResourse,
                           JetsonCurrStatusResourse, LoginResource, LogoutResource
                           )


app_bp = Blueprint('api', __name__)
api = Api(app_bp)


# POST, PUT
api.add_resource(JetsonResource, '/v1/jetson/register/',
                 endpoint='jetson')  # register and update jetson device
# POST, PUT
api.add_resource(UserResource, '/v1/user/register/',
                 endpoint='user')        # register and update user
# GET, POST, PUT
# Create, update and get Alerts
api.add_resource(AlertResource, '/v1/alert/', endpoint='alert')
# POST, GET
api.add_resource(FrameResource, '/v1/log/',
                 endpoint='frame')                # Save frame
# POST
api.add_resource(SafeFrameResource, '/v1/safe/', endpoint='safe')
# GET
api.add_resource(JetsonLastStatusResourse,
                 '/v1/truck/laststatus/', endpoint='laststatus')
# GET
api.add_resource(JetsonCurrStatusResourse, '/v1/truck/currstatus/', endpoint='currstatus')
# POST
api.add_resource(LoginResource, '/v1/login/', endpoint='login')
# GET
api.add_resource(LogoutResource, '/v1/logout/', endpoint='logout')

# api.add_resource(NonAlertFrameResource, '/v1/non-alert-frame/', endpoint='non_alert_frame')
api.add_resource(TruckResource, '/v1/truck/list/', endpoint='trucklist')
# GET
#api.add_resource(LoginResource, '/v1/login/', endpoint='login')
# GET
#api.add_resource(LogoutResource, '/v1/logout/', endpoint='logout')
