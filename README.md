# ServerAPI 

API REST to get and save alerts and frames from computer vision system for mine drivers

### Data base
 In config folder there are two files ( development and production ) you can edit that files to set you our data base and settings.  
 
To Set up you database follow *configdb.sh* file in this repository and after you must run this command in a shell linux console:
```
python migrate.py db init
python migrate.py db migrate
python migrate.py db upgrade
```

After that you must edit **run.py** and change **config** variable (line 4) to environ you want to.  

Note:  
if you get any error about data base, you can run this command to reset you database:
```
python migrate.py db stamp head
```


### Run api

To start server you can follow two simple ways:

##### Virtualenv
Create a virtual environ:

Install virtualenv: **pip install virtualenv** or **sudo apt install virtualenv**   
Create virtualenv: **virtualenv -p python venv**  
Activate virtualenv: **. venv/bin/activate**  
Install libraries: **pip install -r requirements.txt**  
Run API: **python run.py**  


##### Docker
Build and run an docker:

Install docker: **sudo apt install docker.io**  
Build: **docker build -t serverapi:v1 .**  
Run: **docker run --rm -v $PWD:/app -p 5000:5000 -it serverapi:v1**


### Make requests to API

To use this API follow this work flow example  
Note: We will to use [requests](https://requests.readthedocs.io/en/master/) library  


#### Users: (FrontEnd)

Register an user to get a new token

```python
import requests

r = requests.post(url='http://0.0.0.0:5000/api/v1/user/register/', 
                  json={'cur_user': {'username': '<MyName>', 'token': '<MyToken>'}, 
                        'new_user': {'username':'<UserName>', 'password': '<UserPass123>', 'role': '<somerole>', 'email': '<UserEmail>'}
                        }
                  )

if r.status_code == 200:
    print(r.json())
#{'code': 200,
# 'status_code': 'Success',
# 'data': {
#    'id': 1,
#    'token': 'eyJ0eXAiOiJKV1QiLCJh...'
#    }
#}

user_token = r.json()['data']['token']
```

For update user data ( this return a new token )

```python
import requests

username = '<MyName>'

r = requests.put(url='http://0.0.0.0:5000/api/v1/user/register/', 
                 json={'cur_user': {'username': '<MyName>', 'token': '<MyToken>'}, 
                       'new_user': {'username':'<UserName>', 'password': '<UserPass123>', 'role': '<somerole>', 'email': '<UserEmail>'}
                       }
                  )
if r.status_code == 200:
    print(r.json())
#{'code': 200,
# 'status_code': 'Success',
# 'data': {
#    'id': 1,
#    'token': 'eyJ0eXAiOiJKV1QiLCJh...'
#    }
#}

user_token = r.json()['data']['token']
```


from FronEnd

```javascript
<script src="//cdnjs.cloudflare.com/ajax/libs/socket.io/2.2.0/socket.io.js" integrity="sha256-yr4fRk/GU1ehYJPAs8P4JlTgu0Hdsp4ZKrx8bDEDC3I=" crossorigin="anonymous"></script>

<script type="text/javascript" charset="utf-8">
    var token = {user_token};
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/alert');

    socket.emit('get_alert', {'username': '<MyName>', 'token': token}); 

    socket.on('an_alert', function(msg) {
        console.log(msg.data);  // 'new_alert' is printed
        // do something
    });
</script>
```

When *socket.on()* notify an alert, must make this call to get last alerts:  

```python
page = 1  # argument to paginate results (get 20 lats alerts)
r = requests.get(f'http://0.0.0.0:5000/api/v1/alert/?token={user_token}&username={username}&page={page}')
# aditional filters: &behavior=<behavior>&alert_init=<%Y-%m-%d %H:%M:%S>&started=<True|False>&truck_id=<id>
#   started: if alert is closed or open
#   truck_id: only alert from given truck_id
#   alert_init: alerts after than given alert_init

if r.status_code == 200:
    print(r.json())
#{"code": 200,
# "status_code": "Success",
# "data": 
#    {"alerts": [{"behavior": "Safe", "alert_init": "2020-02-19T12:59:02", "id": 14, "truck_id": 2, "started": true, "alert_end": null},
#                {"behavior": "Safe", "alert_init": "2020-02-19T12:59:02", "id": 13, "truck_id": 2, "started": true, "alert_end": null}
#               ]
#    }
#}

alert = r.json()['data']['alerts'][0]

```

To get frames from an alert:
```python
from base64 import b64decode 
page = 1 # argument to paginate results (get 5 lats frames)
r = requests.get(f'http://0.0.0.0:5000/api/v1/log/?token={user_token}&username={username}&page={page}&alert_id={alert_id}') 
# aditional filters: &frame_timestamp=<%Y-%m-%d %H:%M:%S>&frame_index=<index>
#   frame_timestamp: alerts after than given frame_timestamp
#   frame_index: frames after than frame_index

if r.status_code == 200:
    print(r.json())

# {'code': 200, 
#  'status_code': 'Success', 
#  'data': {'frames': [{'frame_index': 0, 
#                       'alert_id': 14, 
#                       'id': 1, 
#                       'frame_timestamp': '2020-02-19T13:15:02', 
#                       'frame_image': 'image in string'},
#                      {'frame_index': 0, 
#                       'alert_id': 14, 
#                       'id': 1, 
#                       'frame_timestamp': '2020-02-19T13:15:02', 
#                       'frame_image': 'image in string'}
#                     ]
#            }
# }

frame_img = r.json()['data']['frames'][0]['frame_image']

# in python to save the image:
with open('image.jpg', 'wb') as fp:
     fp.write(b64decode(frame_img))
```


To get the last frame in truck:

```python
r = requests.get(f'http://0.0.0.0:5000/api/v1/truck/laststatus/?token={user_token}&username=cristian&truck_id=1')

if r.status_code == 200:
    print(r.json())
# {'code': 200,
#  'status_code': 'Success',
#  'data': 
#    {'frame': 
#      {'frame_timestamp': '2020-03-05T13:05:49',
#       'frame_image': 'asdasd4231d..',
#       'frame_index': 0,
#       'id': 2,
#       'truck_id': 1}}}

```
#### Jetson devices:


When the jetson (or any device) starts must will register, and it give their token:  
```python
r = requests.post(url='http://0.0.0.0:5000/api/v1/jetson/register/',
                 json={'mac':'<dc:71:96:53:16:0a>', 'password': '<pass123>', 'name': '<Truck-name>'})

if r.status_code == 200:
    print(r.json())
#{'code': 200,
# 'status_code': 'Success',
# 'data': {
#    'id': 1,
#    'truck_id': 1,
#    'token': 'eyJ0eXAiOiJKV1QiLCJh...'
#    }
#}

jetson_token = r['data']['token']
truck_id = r['data']['truck_id']
```

When an alert is detected the Jetson device  must be init an alert:  

```python
alert_time = dt.now().strftime('%Y-%m-%d %H:%M:%S')
r = requests.post(url='http://0.0.0.0:5000/api/v1/alert/',
                  json={'token':jetson_token,'truck_id': truck_id, 'alert_init': alert_time, 'behavior': 'Safe'})

if r.status_code == 200:
    r.json()
#{'code': 201,
# 'status_code': 'Success',
# 'data': {
#  'id': 1}
#}

alert_id = response['data']['alert_id']
```

After that the Jetson device begin to send frames:  


```python
from base64 import b64encode 

frame_time = dt.now().strftime('%Y-%m-%d %H:%M:%S')
with open('<image/path>', 'rb') as f:
    frame = str(b64encode(f.read()))

r = requests.post('http://0.0.0.0:5000/api/v1/log/',
                  json={'token': jetson_token,'alert_id': alert_id, 'frame_timestamp': frame_time, 'frame': frame})
                        # optional 'frame_index' can be added

if r.status_code == 200:
    print(r.json())

#{'code': 200,
# 'status_code': 'Success',
# 'data': {
#    'id': 1}
#}
```


When alert logging ends the Jetson device close the alert:  

```python
r = requests.put('http://0.0.0.0:5000/api/v1/alert/', json={'token': jetson_token, 'alert_id': alert_id, 'alert_end': '2020-02-19 12:56:02'})

if r.status_code == 201:
    print(r.json())
#{'code': 200,
# 'status_code': 'Success',
# 'data': {
#  'id': 1}
#}
```

To send safe frames:

```python
frame_time = dt.now().strftime('%Y-%m-%d %H:%M:%S')

with open('<image/path>', 'rb') as f:
    frame = str(b64encode(f.read()))

r = requests.post('http://0.0.0.0:5000/api/v1/safe/', 
                  json={'token': jetson_token,'truck_id': truck_id, 'frame_timestamp': frame_time, 'frame': frame})

if r.status_code == 201:
    print(r.json())

# {'code': 200,
#  'status_code': 'Success', 
#  'data': {'safeframe_id': 3}}
```