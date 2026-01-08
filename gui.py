import tkinter as tk
from tkinter import filedialog, messagebox
import os
import psutil
from detector import detect_keylogger_signature, quarantine
from tkinter.ttk import Progressbar
import threading

class KeyloggerDetectorApp:
    def __init__(self, master):
        self.master = master
        master.title("Keylogger Detector")
        master.geometry("800x500")  # Set initial window size

        # Create a frame to contain the background
        self.background_frame = tk.Frame(master, bg='#EFEFEF')  # Light gray background color
        self.background_frame.pack(fill=tk.BOTH, expand=True)  # Fill the entire window

        # Add a label for the background with the text "Keylogger Detector" in bold font
        self.bg_label = tk.Label(self.background_frame, text="Keylogger Detector", font=("Helvetica", 20, "bold"), bg='#EFEFEF')
        self.bg_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)  # Center the label on the background

        # Add a small text box for owner names
        self.owner_label = tk.Label(self.background_frame, text="By- Siddhant,Om,Atharva,Rohan:", bg='#EFEFEF')
        self.owner_label.place(relx=0.5, rely=0.4, anchor=tk.NW)

        # Create a frame to contain the progress bar
        self.progress_frame = tk.Frame(self.background_frame, bg='#EFEFEF')
        self.progress_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        self.progress_label = tk.Label(self.progress_frame, text="", bg='#EFEFEF')
        self.progress_label.pack()

        self.progress_bar = Progressbar(self.progress_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.progress_bar.pack()

        # Create a frame to contain the buttons
        self.button_frame = tk.Frame(self.background_frame, bg='white')  # White background for the button frame
        self.button_frame.pack(side=tk.BOTTOM, pady=20)  # Position at the bottom center

        self.label = tk.Label(self.button_frame, text="Choose an option:")
        self.label.pack()

        self.select_file_button = tk.Button(self.button_frame, text="Select Signature List", command=self.select_file, font=("Helvetica", 12))
        self.select_file_button.pack(side="left", padx=10)

        self.detect_button = tk.Button(self.button_frame, text="Full System Scan", command=self.detect_keyloggers, font=("Helvetica", 12))
        self.detect_button.pack(side="left", padx=10)

        self.quit_button = tk.Button(self.button_frame, text="Quit", command=master.quit, font=("Helvetica", 12))
        self.quit_button.pack(side="left", padx=10)

        self.selected_file = ""

    def select_file(self):
        self.selected_file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.selected_file:
            messagebox.showinfo("File Selected", f"Signature list selected: {self.selected_file}")

    def detect_keyloggers(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a signature list file.")
            return

        # Define a function to perform the scanning process
        def scan_process():
            detected_files = []

            process_list = list(psutil.process_iter(['pid', 'name']))  # Convert generator to list
            total_processes = len(process_list)
            current_process = 0
            self.progress_label.config(text="Scanning processes...")
            self.progress_bar["value"] = 0
            self.progress_bar["maximum"] = total_processes
            for proc in process_list:
                try:
                    current_process += 1
                    self.progress_bar["value"] = current_process
                    self.progress_label.config(text=f"Scanning process: {proc.info['name']}")
                    self.master.update_idletasks()
                    proc_name = proc.info['name']
                    signature_info = detect_keylogger_signature(proc_name)
                    if signature_info:
                        detected_files.append((proc_name, signature_info))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

                # Scanning files...
            total_files = sum(len(files) for _, _, files in os.walk("/"))
            current_file = 0
            self.progress_label.config(text="Scanning files...")
            self.progress_bar["value"] = 0
            self.progress_bar["maximum"] = total_files
            for root, dirs, files in os.walk("/"):
                for file in files:
                    current_file += 1
                    self.progress_bar["value"] = current_file
                    self.progress_label.config(text=f"Scanning file: {file}")
                    self.master.update_idletasks()
                    file_path = os.path.join(root, file)
                    signature_info = detect_keylogger_signature(file_path)
                    if signature_info:
                        detected_files.append((file_path, signature_info))

            # Show results in messagebox
            if detected_files:
                quarantine_option = messagebox.askquestion("Keyloggers Detected",
                                                           f"{len(detected_files)} keyloggers detected. "
                                                           "Do you want to quarantine them?")
                if quarantine_option == "yes":
                    quarantine([file for file, _ in detected_files])
                    messagebox.showinfo("Quarantine Successful", "Keyloggers quarantined successfully.")
                else:
                    messagebox.showinfo("Quarantine Skipped", "Keyloggers were not quarantined.")

                alert_message = "\n".join([f"{file}: {info}" for file, info in detected_files])
                messagebox.showinfo("Keyloggers Detected", alert_message)
            else:
                messagebox.showinfo("No Keyloggers Detected", "No keyloggers were detected.")

        # Create a thread to run the scanning process
        scan_thread = threading.Thread(target=scan_process)
        scan_thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    app = KeyloggerDetectorApp(root)
    root.mainloop()
