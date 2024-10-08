import tkinter as tk
from tkinter import messagebox, ttk
import threading
import subprocess
import tempfile
import os
import asyncio
from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster
import ctypes  # Import ctypes for Windows API calls

# Addon class for redirecting a specific domain to an IP
class RedirectAddon:
    def __init__(self, domain, ip):
        # Store the domain and IP that will be used for redirection
        self.domain = domain
        self.ip = ip

    # Function that handles each HTTP request
    def request(self, flow: http.HTTPFlow):
        # If the request's host matches the provided domain, redirect it to the IP address
        if flow.request.host == self.domain:
            print(f"Redirecting {self.domain} to {self.ip}")
            flow.request.host = self.ip  # Change the request host to the IP address
            flow.request.headers["Host"] = self.domain  # Keep the original domain in the Host header
        else:
            print(f"Ignoring request to {flow.request.host}")  # Ignore other requests

# Main application class for the domain redirection tool
class App:
    def __init__(self, master):
        self.master = master
        master.title("SS Domain Redirection v1.0.1 - by Rick Moore")
        master.geometry("400x250")
        master.minsize(400, 250)
        
        # Set the window background to black
        master.configure(bg='#121212')
        
        # Set the title bar color to black (Windows only)
        self.set_title_bar_color(master)
        
        # Create a style for themed widgets
        self.style = ttk.Style(master)
        self.style.theme_use('default')
        
        # Define light sky blue color
        sky_blue = '#87CEEB'
        
        # Configure styles for various widget types
        self.style.configure('TLabel', foreground=sky_blue, background='#121212', font=('Arial', 12))
        self.style.configure('TEntry', foreground='#E0E0E0', background='black', fieldbackground='black', insertcolor='#E0E0E0', borderwidth=1, font=('Arial', 12))
        self.style.configure('TButton', foreground='#121212', background=sky_blue, font=('Arial', 12))
        self.style.map('TButton', background=[('active', '#5F9EA0')])  # Slightly darker blue when button is pressed
        
        # Create a custom style for Entry widgets with a sky blue border
        self.style.layout('SkyBlueEntry.TEntry', [('Entry.plain.field', {'children': [(
            'Entry.background', {'children': [(
                'Entry.padding', {'children': [(
                    'Entry.textarea', {'sticky': 'nswe'}
                )], 'sticky': 'nswe'}
            )], 'sticky': 'nswe'}
        )], 'border': '1', 'sticky': 'nswe'})])
        self.style.configure('SkyBlueEntry.TEntry', 
                             bordercolor=sky_blue,
                             lightcolor=sky_blue,
                             darkcolor=sky_blue)
        
        # Main frame
        main_frame = ttk.Frame(master, style='TFrame')
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        self.style.configure('TFrame', background='#121212')

        # Domain Name Input
        self.domain_label = ttk.Label(main_frame, text="Domain Name:")
        self.domain_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        self.domain_entry = ttk.Entry(main_frame, width=40, style='SkyBlueEntry.TEntry')
        self.domain_entry.grid(row=0, column=1, padx=10, pady=10)

        # IP Address Input
        self.ip_label = ttk.Label(main_frame, text="IP Address:")
        self.ip_label.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        self.ip_entry = ttk.Entry(main_frame, width=40, style='SkyBlueEntry.TEntry')
        self.ip_entry.grid(row=1, column=1, padx=10, pady=10)

        # ON/OFF Button
        self.toggle_button = ttk.Button(main_frame, text="Start Redirection", command=self.toggle_redirection)
        self.toggle_button.grid(row=2, column=0, columnspan=2, padx=10, pady=20)

        # Status Label
        self.status_label = ttk.Label(main_frame, text="Status: OFF")
        self.status_label.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        # Variables
        self.proxy_thread = None
        self.is_running = False
        self.mitm = None
        self.temp_dir = None

    # Function to set the title bar color to black (Windows only)
    def set_title_bar_color(self, root):
        try:
            # Windows only: change title bar color
            root.update()
            DWMWA_CAPTION_COLOR = 35
            hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            rendered_color = ctypes.c_uint(0x00000000)  # ARGB color format (0x00BBGGRR)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 
                DWMWA_CAPTION_COLOR,
                ctypes.byref(rendered_color),
                ctypes.sizeof(rendered_color)
            )
        except Exception as e:
            print(f"Failed to set title bar color: {e}")

    def toggle_redirection(self):
        if not self.is_running:
            domain = self.domain_entry.get().strip()
            ip = self.ip_entry.get().strip()

            if not domain or not ip:
                messagebox.showerror("Input Error", "Please enter both domain and IP address.")
                return

            self.start_proxy(domain, ip)
            self.start_browser(domain)
            self.toggle_button.config(text="Stop Redirection")
            self.status_label.config(text="Status: ON")
            self.is_running = True
        else:
            self.stop_proxy()
            self.toggle_button.config(text="Start Redirection")
            self.status_label.config(text="Status: OFF")
            self.is_running = False

    # Function to start the proxy thread and redirection logic
    def start_proxy(self, domain, ip):
        self.addon = RedirectAddon(domain, ip)  # Create an instance of RedirectAddon
        self.proxy_thread = threading.Thread(target=self.run_proxy)  # Create a new thread for the proxy
        self.proxy_thread.start()  # Start the proxy thread

    # Function that runs mitmproxy in a separate thread
    def run_proxy(self):
        from mitmproxy import options

        # Asynchronous function to run mitmproxy
        async def mitmproxy_run():
            # mitmproxy options, such as listening on localhost:8080
            opts = options.Options(
                listen_host='127.0.0.1',
                listen_port=8080,
                ssl_insecure=True  # Allow insecure SSL connections (self-signed, etc.)
            )
            self.mitm = DumpMaster(opts)  # Initialize mitmproxy's DumpMaster
            self.mitm.addons.add(self.addon)  # Add our redirection addon to mitmproxy
            await self.mitm.run()  # Start mitmproxy

        try:
            # Run mitmproxy asynchronously
            asyncio.run(mitmproxy_run())
        except Exception as e:
            print(f"Proxy stopped: {e}")

    # Function to stop the proxy and clean up resources
    def stop_proxy(self):
        if self.mitm:
            # Gracefully shut down mitmproxy
            asyncio.run(self.mitm.shutdown())
            self.proxy_thread.join()  # Wait for the thread to finish
            self.mitm = None  # Reset the mitmproxy instance
            # Clean up the temporary directory if it exists
            if self.temp_dir and os.path.exists(self.temp_dir):
                try:
                    os.rmdir(self.temp_dir)  # Remove the directory if it's empty
                except OSError:
                    pass  # Ignore if directory is not empty
                self.temp_dir = None

    # Function to launch Chrome with proxy settings and open the target domain
    def start_browser(self, domain):
        # Path to the Chrome executable, update this path as needed
        chrome_path = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
        if not os.path.exists(chrome_path):
            messagebox.showerror("Chrome Not Found", f"Chrome executable not found at {chrome_path}. Please update the path in the script.")
            return

        # Arguments for Chrome to use the proxy and other settings
        proxy_argument = '--proxy-server=127.0.0.1:8080'
        incognito_argument = '--incognito'
        new_window_argument = '--new-window'
        ignore_cert_errors_argument = '--ignore-certificate-errors'  # Ignore SSL certificate errors
        # Create a temporary directory for Chrome's user data
        self.temp_dir = tempfile.mkdtemp()
        user_data_dir_argument = f'--user-data-dir={self.temp_dir}'
        # Open the URL with HTTP protocol to ensure mitmproxy can intercept
        url = f'http://{domain}'

        # Launch Chrome with the specified arguments
        subprocess.Popen([
            chrome_path,
            new_window_argument,
            incognito_argument,
            proxy_argument,
            ignore_cert_errors_argument,
            user_data_dir_argument,
            url
        ])

    # Function to handle window close event and ensure clean shutdown
    def on_closing(self):
        self.stop_proxy()  # Stop the proxy when closing the window
        self.master.destroy()  # Close the application window

# Main entry point of the program
if __name__ == "__main__":
    root = tk.Tk()  # Create the main Tkinter window
    app = App(root)  # Create an instance of the App class
    root.protocol("WM_DELETE_WINDOW", app.on_closing)  # Bind the window close event to on_closing function
    root.mainloop()  # Start the Tkinter event loop