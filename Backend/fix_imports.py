import os

out_dir = r'a:\Hackathon\PNB - Crypto Scanner\Backend\app\api\routers'
for f in os.listdir(out_dir):
    if f.endswith('.py') and f != 'common.py':
        filepath = os.path.join(out_dir, f)
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read()
        
        target = 'router = APIRouter(tags=["Scanner"])'
        replacement = target + '\nfrom .common import *\n'
        content = content.replace(target, replacement)
        
        with open(filepath, 'w', encoding='utf-8') as file:
            file.write(content)
            
print('Updated imports.')
