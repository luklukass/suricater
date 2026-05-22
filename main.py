import ctypes
import tkinter as tk

from app import App

ctypes.windll.shcore.SetProcessDpiAwareness(1)

if __name__ == '__main__':
    root = tk.Tk()
    App(root)
    root.mainloop()
