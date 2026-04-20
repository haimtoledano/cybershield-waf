import urllib.request
import urllib.error
import json

data = json.dumps({'username':'superadmin', 'password':'ChangeMeNow123!'}).encode('utf-8')
req = urllib.request.Request('http://localhost:8000/api/auth/login', data=data, headers={'Content-Type':'application/json'})
try:
    res = urllib.request.urlopen(req)
    print(res.read().decode('utf-8'))
except urllib.error.HTTPError as e:
    print(e.read().decode('utf-8'))
