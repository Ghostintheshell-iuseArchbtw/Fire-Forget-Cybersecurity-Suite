import sys
import subprocess
import time
import re
from PyQt5.QtWidgets import QApplication, QDialog, QPushButton, QTextEdit, QVBoxLayout, QLabel, QLineEdit, QGridLayout
from PyQt5.QtCore import QTimer
import threading

class GobusterRustscanNiktoSQLMapGUI:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.window = QDialog()
        self.window.setWindowTitle("Fire&Forget")
        self.layout = QGridLayout()

        self.label = QLabel("TARGET_TO_PWN:")
        self.url_input = QLineEdit()
        self.text_edit = QTextEdit()
        self.button_fire_forget = QPushButton("FIRE_AND_FORGET")
        self.button_flee = QPushButton("FLEE_THE_FIGHT")

        self.layout.addWidget(self.label, 0, 0)
        self.layout.addWidget(self.url_input, 0, 1, 1, 2)
        self.layout.addWidget(self.text_edit, 1, 0, 1, 3)
        self.layout.addWidget(self.button_fire_forget, 2, 0, 1, 2)
        self.layout.addWidget(self.button_flee, 2, 2, 1, 1)

        self.window.setLayout(self.layout)
        self.button_fire_forget.clicked.connect(self.run_scan)
        self.button_flee.clicked.connect(self.flee)

        self.countdown_thread = None

        self.window.show()
        sys.exit(self.app.exec_())

    def run_scan(self):
        # Disable "FIRE&FORGET" button during the countdown
        self.button_fire_forget.setEnabled(False)

        target_url = self.url_input.text()

        # Get screen resolution
        screen_resolution_command = "xrandr | grep '*' | awk '{print $1}'"
        screen_resolution = subprocess.check_output(screen_resolution_command, shell=True).decode("utf-8").strip().split("x")
        screen_width, screen_height = int(screen_resolution[0]), int(screen_resolution[1])

        # Calculate center position and increase size
        central_terminal_width = 160
        central_terminal_height = 40
        central_terminal_x = (screen_width - central_terminal_width) // 2
        central_terminal_y = (screen_height - central_terminal_height) // 2

        # Launch central terminal at the center with countdown
        central_terminal_command = (
            f"xterm -geometry {central_terminal_width}x{central_terminal_height}+{central_terminal_x}+{central_terminal_y} "
            f"-hold -e 'echo -e "
            f"\"\n\nWelcome to the Fire&Forget Cybersecurity Suite!\n\nLaunching powerful tools for penetration testing...\n"
            f"This central terminal controls and entertains you while you wait.\n\nFIRE AND FORGET ENGAGED!\nLOADING TOOLS, SETTING TARGET,\n"
            f"AIMING TOOLS, FIRING!\"\n; for i in $(seq 5 -1 1); do echo \"Starting in \$i seconds...\"; sleep 1; done; bash'"
        )
        subprocess.Popen(central_terminal_command, shell=True)

        # Create a thread to enable the "FIRE&FORGET" button after countdown finishes
        self.countdown_thread = threading.Thread(target=self.enable_button_after_countdown)
        self.countdown_thread.start()

    def enable_button_after_countdown(self):
        # Sleep to wait for the countdown to finish
        time.sleep(6)

        # Enable the "FIRE&FORGET" button after countdown
        self.button_fire_forget.setEnabled(True)

        # Run Gobuster in dir mode
        target_url = self.url_input.text()
        gobuster_command = (
            f"xterm -geometry 80x24+0+0 -hold -e 'sudo gobuster dir -u {target_url}:80/ -w /usr/share/seclists/Discovery/Web-Content/dirsearch.txt --no-error; bash'"
        )
        subprocess.Popen(gobuster_command, shell=True)

        # Run Rustscan to find potential web servers
        rustscan_command = (
         f"xterm -geometry 80x24+0-0 -hold -e 'rustscan -a {target_url} -t 500 -b 2000 -u 6000 -- -sV -o rustscan_output.txt; bash'"  
#	 f"xterm -geometry 80x24+0-0 -hold -e 'rustscan -a {target_url} -t 500 -b 2000 -u 6000 -- -sV --script vuln -o rustscan_output.txt; bash'"
        )
        subprocess.Popen(rustscan_command, shell=True)

        # Run Nikto with the flags -h http://example.com
        nikto_command = f"xterm -geometry 80x24-0-0 -hold -e 'nikto -h {target_url} -o nikto_output.txt; bash'"
        subprocess.Popen(nikto_command, shell=True)

        # Launch msfconsole in a fourth terminal
        msfconsole_command = f"xterm -geometry 80x24-0+0 -hold -e 'msfconsole; bash'"
        subprocess.Popen(msfconsole_command, shell=True)

        # Check if Rustscan found potential web servers
        rustscan_output = subprocess.check_output("cat rustscan_output.txt", shell=True).decode("utf-8")
        web_server_ports = re.findall(r"(\d{1,5})/tcp\s+open\s+(?:http|https)", rustscan_output)

        if web_server_ports:
            # If potential web servers found, run SQLMap on each
            for port in web_server_ports:
                sqlmap_command = f"xterm -geometry 80x24-0+0 -hold -e 'sqlmap -u http://{target_url}:{port} --dbs; bash'"
                subprocess.Popen(sqlmap_command, shell=True)

    def flee(self):
        # Kill all opened terminals
        subprocess.run("pkill xterm", shell=True)
        sys.exit()

if __name__ == "__main__":
    gui = GobusterRustscanNiktoSQLMapGUI()
