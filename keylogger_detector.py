#!/usr/bin/env python3

import os
import psutil

def check_process_names():
    """Check for suspicious process names."""
    suspicious_names = ["keylogger", "logkeys", "xinput", "pylog"]
    found = []

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_name = proc.info['name'].lower()
            for suspicious in suspicious_names:
                if suspicious in process_name:
                    found.append((proc.info['pid'], process_name))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return found

def check_keyboard_hooks():
    """Check for processes interacting with the keyboard."""
    suspicious_procs = []
    try:
        for pid in os.listdir('/proc'):
            if pid.isdigit():
                fd_dir = f"/proc/{pid}/fd"
                if os.path.exists(fd_dir):
                    for fd in os.listdir(fd_dir):
                        try:
                            link = os.readlink(os.path.join(fd_dir, fd))
                            if 'keyboard' in link.lower():
                                process_name = psutil.Process(int(pid)).name()
                                suspicious_procs.append((pid, process_name))
                        except (FileNotFoundError, psutil.NoSuchProcess):
                            pass
    except Exception as e:
        print(f"Error during keyboard hook detection: {e}")
    
    return suspicious_procs

def main():
    print("=== Basic Keylogger Detector ===")
    
    # Check suspicious process names
    suspicious_names = check_process_names()
    if suspicious_names:
        print("[!] Found suspicious processes:")
        for pid, name in suspicious_names:
            print(f"    PID: {pid}, Name: {name}")
    else:
        print("[+] No suspicious process names detected.")
    
    # Check keyboard hooks
    keyboard_hooks = check_keyboard_hooks()
    if keyboard_hooks:
        print("[!] Found processes interacting with the keyboard:")
        for pid, name in keyboard_hooks:
            print(f"    PID: {pid}, Name: {name}")
    else:
        print("[+] No suspicious keyboard hooks detected.")
    
    print("=== Scan Complete ===")

if __name__ == "__main__":
    main()
