import http.server
import os
import socket
import socketserver
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

import wmi

START_PORT = 8000
END_PORT = 9000

_dir = None


def get_ip_address():
    wmi_object = wmi.WMI()
    wmi_query = "select IPAddress,DefaultIPGateway from Win32_NetworkAdapterConfiguration where IPEnabled=TRUE"
    wmi_output = wmi_object.query(wmi_query)

    for default_network in wmi_output:
        if default_network.DefaultIPGateway is not None:
            return default_network.IPAddress[0]


def find_unused_port(ip_address):
    for port in range(START_PORT, END_PORT + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))
            if result != 0:
                return port
    return None


def get_url():
    ip_address = get_ip_address()
    return f"http://{ip_address}:{find_unused_port(ip_address)}/"


class HTTPServerThread(threading.Thread):
    def __init__(self, ip, port, directory, output_text):
        super().__init__()
        self.ip = ip
        self.port = port
        self.directory = directory
        self.handler = CustomRequestHandler
        self.httpd = None
        self.server_running = threading.Event()
        self.output_text = output_text

    def run(self):
        os.chdir(self.directory)
        self.redirect_output_to_text_widget()
        self.httpd = socketserver.TCPServer((self.ip, self.port), self.handler)
        self.server_running.set()
        try:
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(
                tk.END,
                f"HTTP server running at http://{self.ip}:{self.port}/, serving from {self.directory}\n",
            )
            self.httpd.serve_forever()

        except Exception as e:
            print(f"HTTP server error: {e}")

        finally:
            self.server_running.clear()
            self.restore_output()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()

    def is_running(self):
        return self.server_running.is_set()

    def redirect_output_to_text_widget(self):
        sys.stdout = StreamToTkText(self.output_text)
        sys.stderr = StreamToTkText(self.output_text)

    def restore_output(self):
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__


class StreamToTkText:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, text):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, text)
        self.text_widget.see(tk.END)
        self.text_widget.config(state=tk.DISABLED)

    def flush(self):
        pass


class CustomRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        if "." in self.path:
            file_extension = self.path.split(".")[-1]
            if file_extension.lower() not in ["html", "htm"]:
                self.send_header("Content-Disposition", "attachment")
        super().end_headers()

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionAbortedError, BrokenPipeError):
            pass


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("HTTP Server")
        self.server_thread = None

        frame = tk.Frame(self.root)
        frame.pack(padx=20, pady=20)

        text = f'Enter the following URL in the browser of the device you want to access the files.\n"{get_url()}"'

        self.label = tk.Label(
            frame, text=text, font=("Helvetica", 16, "bold"), wraplength=500
        )
        self.label.pack(side=tk.LEFT, padx=(0, 10))

        self.stop_button = tk.Button(
            self.root, text="Stop Server", command=self.stop_server, state=tk.NORMAL
        )
        self.stop_button.pack(pady=10)

        self.select_dir_button = tk.Button(
            frame, text="Select Directory", command=self.select_directory
        )
        self.select_dir_button.pack(side=tk.LEFT, padx=(20, 0))

        self.output_text = tk.Text(self.root, wrap=tk.WORD, height=10, width=80)
        self.output_text.pack(padx=20, pady=(0, 20))
        self.output_text.config(state=tk.DISABLED)

        self.start_server()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def select_directory(self):
        global _dir
        selected_dir = filedialog.askdirectory(
            initialdir=os.getcwd(), title="Select Directory"
        )
        if selected_dir:
            _dir = selected_dir
            self.start_server()

    def start_server(self):
        if not _dir:
            self.add_output_message("Please select a directory first.\n")
            return

        if not self.server_thread or not self.server_thread.is_alive():
            ip_addr = get_ip_address()
            self.server_thread = HTTPServerThread(
                ip_addr, find_unused_port(ip_addr), _dir, self.output_text
            )
            self.server_thread.start()
        else:
            messagebox.showinfo(
                "Server Already Running", "HTTP server is already running."
            )

    def stop_server(self):
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.stop()
            self.server_thread.join(timeout=1)

            if not self.server_thread.is_alive():
                self.add_output_message("HTTP server stopped successfully.\n")

                self.select_dir_button.config(state=tk.NORMAL)

        else:
            messagebox.showinfo(
                "Server Not Running", "HTTP server is not currently running."
            )

    def on_closing(self):
        if self.server_thread and self.server_thread.is_alive():
            self.stop_server()

        self.root.destroy()

    def add_output_message(self, message):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, message)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
