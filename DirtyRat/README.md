🐀 DirtyRAT — Educational Remote Access Tool

DirtyRAT is a lightweight Remote Access Tool (RAT) built in Python for educational purposes only.
It allows you to experiment with keylogging, screenshots, shell commands, and system/process info over a basic TCP connection.

This project was created as part of my learning journey into ethical hacking, scripting, and penetration testing.

⚙️ Features

📡 Reverse TCP connection (client to server)

⌨️ Keystroke logging

📷 Screenshot capture

💻 System information retrieval

💎 Shell command execution

🔍 List running processes

❌ Kill process by PID

🔧 Requirements

Python 3.8+

OS: Windows (for client), server can run on any OS with Python

Python packages:

pynput

psutil

Pillow

Install dependencies with:

pip install -r requirements.txt

🚀 Getting Started

Clone the repo and go to the project folder:

git clone https://github.com/yourusername/dirtylabs.git
cd dirtylabs/DirtyRAT

Install requirements:

pip install -r requirements.txt

Run the server (on attacker's machine):

python ser2.py

Run the client (on target machine):

python cli2.py

⚠️ Ensure both machines are on the same LAN or connected via VPN.

💻 Server Usage Example

rat> help
Commands: help, get_logs, screenshot, shell <cmd>, system_info, list_processes, kill_process <pid>

rat> system_info
{'OS': 'Windows-11', 'CPU': 'Intel i7', 'RAM': '16.0 GB', 'User': 'target'}

rat> screenshot
[+] Screenshot saved as screenshots/screenshot_20250704_173922.png

rat> shell whoami
target-pc\\target

📌 Notes

Screenshots are saved in screenshots/

Binary data fallback goes to unknown/

Keylogs may appear empty until some keys are typed

Shell output uses .decode(errors="ignore") to avoid crashes

Windows Defender or antivirus may detect keylogger behavior

Admin privileges may be needed for firewall access or keyboard hooks

⚠️ Disclaimer

This software is provided for educational and ethical testing purposes only.
By using this tool, you agree to:

Only test it in environments you own or have permission to use

Never deploy it in real-world networks without consent

The author is not responsible for any damage, loss, or misuse.

🧐 Final Note

DirtyRAT is my first attempt to build a remote tool as I enter the world of cybersecurity and scripting.
It still needs many improvements, but it helped me learn a lot about sockets, shell interaction, and system control.

Pull requests, issues, and ideas are always welcome ✨

