import os, sys
from datetime import datetime

SERVER_START = datetime.now().strftime('%Y%m%d_%H%M%S')


if os.path.exists('./logs') == False:
        os.mkdir('./logs')

def print_message(*args):
    
    with open(f'./logs/ApiLog_{SERVER_START}.txt', 'a') as log_file:
        for arg in args:
            if type(arg) == list or type(arg) == tuple:
                for item in arg:
                    now = current_time()
                    log_file.write(str(now) + ': ' + str(item) + '\n')
                    print(str(now) + ': ' + str(item))
            
            elif type(arg) == dict:
                for key in arg:
                    now = current_time()
                    
                    log_file.write(str(now) + ': ' + str(key) + ': ' + str(arg[key]) + '\n')
                    print(str(now) + ': ' + str(key) + ': ' + str(arg[key]))
            else:   
                now = current_time()
                     
                log_file.write(str(now) + ': ' + str(arg) + '\n')
                print(str(now) + ': ' + str(arg))

def current_time():
    now = datetime.now().utcnow().strftime('%y-%m-%d %H:%M:%S')
    return now

print_message('Server start time: ', SERVER_START)