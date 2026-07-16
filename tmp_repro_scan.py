import app
import time
from app import _start_scan_internal

scan_id = _start_scan_internal('https://juice-shop.herokuapp.com', ['nmap'], ['A01'], username='tester')
print('scan_id', scan_id)
for i in range(30):
    time.sleep(1)
    s = app.scan_sessions.get(scan_id)
    if s:
        print('status', s.get('status'), 'events', s.get('events', [])[-3:])
        if s.get('status') == 'done':
            break
final = app.scan_sessions.get(scan_id)
print('final_status', final.get('status') if final else None)
print('results_keys', list((final.get('results') or {}).keys()) if final else None)
print('results', final.get('results') if final else None)
