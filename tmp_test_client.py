import os
import sys
import time
from werkzeug.security import generate_password_hash
import app as app_module

client = app_module.app.test_client()

# Create a user if needed
user = app_module.db.get_user_by_username('tester')
if not user:
    app_module.db.create_initial_user('tester', generate_password_hash('tester123'), role='auditor')

resp = client.post('/login', data={'username': 'tester', 'password': 'tester123'}, follow_redirects=True)
print('login_status', resp.status_code)
print('login_text', resp.get_data(as_text=True)[:200])

scan_resp = client.post('/api/scan/start', json={
    'target': 'https://juice-shop.herokuapp.com',
    'tools': ['nmap'],
    'owasp_ids': ['A01'],
    'project_id': None
})
print('start_status', scan_resp.status_code)
print('start_body', scan_resp.get_json())
if scan_resp.status_code == 200:
    scan_id = scan_resp.get_json()['scan_id']
    print('scan_id', scan_id)
    for i in range(40):
        status_resp = client.get(f'/api/scan/status/{scan_id}')
        print('status_iter', i, status_resp.status_code, status_resp.get_json())
        if status_resp.get_json().get('status') in ('done', 'error'):
            break
        time.sleep(1)
    result_resp = client.get(f'/api/scan/result/{scan_id}')
    print('result_status', result_resp.status_code)
    print('result_body', result_resp.get_json())
