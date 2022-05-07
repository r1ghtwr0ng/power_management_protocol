import os
import re
import time
import psutil
import shutil
import platform
from threading import Thread

SUSPENDING = False
SUSPEND_TIME = 10
COMMANDS = ['PWR_STAT', 'BTRY_LVL', 'SUSPND', 'REBOOT', 'PWROFF', 'END_CONN'] # Available commands

# Fetch the width of the current terminal
def get_terminal_width():
    size = shutil.get_terminal_size((80, 40))
    return size.columns

# Print program banner
def print_banner(text):
    term_width = get_terminal_width()
    centering_left = int((term_width-len(text)+2)/2)
    centering_right = term_width - len(text) - 2 - centering_left
    print(f'\n\n{"-"*term_width}\n{"<"*centering_left} {text} {">"*centering_right}\n{"-"*term_width}\n\n')

# Print all available commands with selection numbers
def print_commands():
    for i in range(len(COMMANDS)):
        print(f'  [{i+1}] {COMMANDS[i]}')
    print('  [Q] Quit')

# Whenever a PWROFF, REBOOT or SUSPND command is received, start a timer before running it
def critical_command(plt, command):
    global SUSPENDING
    if SUSPENDING:
        return
    SUSPENDING = True
    time.sleep(SUSPEND_TIME)
    if bool(re.match('Windows', plt)):
        # Powershell commands
        if command == 'PWROFF':
            os.system('shutdown /t 0')
            return
        elif command == 'REBOOT':
            os.system('shutdown /r /t 0')
            return
        elif command == 'SUSPND':
            os.system('rundll32.exe powrprof.dll,SetSuspendState 0,1,0')
            return
        print(f'[!] Unrecognized command {command}')
        return
    # Attempt to run bash commands for non-Windows OS-es
    # Powershell commands
    if command == 'PWROFF':
        subprocess.run(['poweroff'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    elif command == 'REBOOT':
        subprocess.run(['reboot'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    elif command == 'SUSPND':
        # Make sure to add the shell script with the appropriate suspend commands for your system
        subprocess.run(['../suspend.sh'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    print(f'[!] Unrecognized command {command}')
    return
        
# Run battery commands and pass important ones to critical_command
def run_cmd(command):
    battery = psutil.sensors_battery()
    if command == 'PWR_STAT':
        return 'PLUGGED IN' if battery.power_plugged else 'NOT PLUGGED IN'
    elif command == 'BTRY_LVL':
        return str(f'{battery.percent}%')
    elif command == 'END_CONN':
        return 'CLOSED_CONN'
    plt = platform.platform()
    Thread(target=critical_command, args=(plt, command))
    return f'{command} in {SUSPEND_TIME} sec'
