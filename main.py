import tkinter as tk
from gui import KeyloggerDetectorApp

def main():
    root = tk.Tk()
    app = KeyloggerDetectorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
