import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
import re
import webbrowser
import ctypes

ctypes.windll.shcore.SetProcessDpiAwareness(1)


class SuricataRuleParser:
    def __init__(self):
        self.keyword_content = re.compile(r'content:"([^"]+)"')
        self.keyword_nocase = re.compile(r'\bnocase\b')

    def extract_content(self, rule_text):
        matches = self.keyword_content.findall(rule_text)
        return matches

    def has_nocase(self, rule_text):
        return bool(self.keyword_nocase.search(rule_text))


# Function to handle rule selection and display it
# Function to handle rule selection and display it
def select_rule(event):
    selected_rule_index = rule_combobox.current()
    if selected_rule_index != -1 and selected_rule_index < len(filtered_rules):
        selected_rule = filtered_rules[selected_rule_index]
        rule_text.config(state=tk.NORMAL)
        rule_text.delete("1.0", tk.END)
        rule_text.insert(tk.END, selected_rule)
        rule_text.tag_configure("center", justify='center')
        rule_text.yview_moveto(0.0)
        rule_text.tag_add("center", "1.0", "end")
        rule_text.config(state=tk.DISABLED)

        # Extract all payload keywords
        payload_keywords = suricata_parser.extract_content(selected_rule)
        nocase_info = "True" if suricata_parser.has_nocase(selected_rule) else "False"

        content_text = ""
        if payload_keywords:
            for keyword in payload_keywords:
                content_text += f"{keyword}\n"

        content_box.config(state=tk.NORMAL)
        content_box.delete("1.0", tk.END)
        content_box.insert(tk.END, content_text)
        content_box.tag_add("center", "1.0", "end")
        content_box.config(state=tk.DISABLED)

        # Update the nocase information
        nocase_box.config(state=tk.NORMAL)
        nocase_box.delete("1.0", tk.END)
        nocase_box.insert(tk.END, nocase_info)
        nocase_box.config(state=tk.DISABLED)
def filter_rules(search_text):
    matching_msgs = []
    matching_rules = []
    for rule in rules:
        if search_text.lower() in rule.lower():
            matching_rules.append(rule)
            match = re.search(r'msg:"([^"]+)"', rule)
            if match:
                matching_msgs.append(match.group(1))
    return matching_msgs, matching_rules

def update_combobox_options(search_text):
    matching_msgs, matching_rules = filter_rules(search_text)
    rule_combobox['values'] = matching_msgs
    global filtered_rules
    filtered_rules = matching_rules




def choose_file_action():
    global filtered_rules
    file_path = filedialog.askopenfilename(title="Choose a File")
    if file_path:
        with open(file_path, 'r') as file:
            rules.clear()
            msg_values.clear()
            for line in file:
                if re.search(r'\bsid\b', line):
                    cleaned_line = line.lstrip('#').strip()
                    rules.append(cleaned_line)
                    match = re.search(r'msg:"([^"]+)"', cleaned_line)
                    if match:
                        msg_values.append(match.group(1))
            filtered_rules = rules.copy()
            rule_combobox['values'] = msg_values

def open_documentation():
    webbrowser.open('suricata-latest\index.html')
# Create the main window

def export_rules():
    search_text = search_entry.get().lower()
    matching_rules = [rule for rule in rules if search_text in rule.lower()]

    if not matching_rules:
        messagebox.showinfo("Export", "No matching rules found.")
        return

    # Ask user for the file name and location
    file_path = filedialog.asksaveasfilename(defaultextension=".rules", filetypes=[("Suricata Rules", "*.rules")])

    if file_path:
        try:
            with open(file_path, 'w') as export_file:
                for rule in matching_rules:
                    export_file.write(rule + '\n')

            messagebox.showinfo("Export Successful", f"The rules have been exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred during export: {str(e)}")

root = tk.Tk()
root.title("SURICATER")
root.iconbitmap('assets/img/logo.ico')
root.option_add("*TCombobox*Listbox.font", "Helevetica 10")

# Set the initial window size
root.minsize(900, 600)
root.geometry(f"1200x900")
menu_font = ("Helvetica", 10)
# Create a menu bar
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)


# Create a File menu
signatures_menu = tk.Menu(menu_bar, tearoff=0, font=menu_font)
help_menu = tk.Menu(menu_bar, tearoff=0, font=menu_font)

menu_bar.add_cascade(label="Signatures", menu=signatures_menu)
menu_bar.add_cascade(label="Help", menu=help_menu)


# Add items to the File menu
signatures_menu.add_command(label="Choose", command=choose_file_action)
signatures_menu.add_command(label="Create")
signatures_menu.add_command(label="Export", command=export_rules)
help_menu.add_command(label="Documentation", command=open_documentation)
help_menu.add_command(label="Info")

# Initialize rules and msg_values
rules = []
msg_values = []
suricata_parser = SuricataRuleParser()
filtered_rules = rules.copy()

# Create a Label widget for the search title
search_label = tk.Label(root, text="Search:", font=("Helvetica", 10))
search_label.grid(row=0, column=0, padx=10, sticky="w")

# Create a search box Entry widget with a placeholder
search_entry = tk.Entry(root, width=200, font=("Helvetica", 11))
search_entry.grid(row=1, column=0, padx=10, pady=(0, 13), sticky="w")

# Create a Combobox to select the "msg" option
rules_label = tk.Label(root, text="Rules:", font=("Helvetica", 10))
rules_label.grid(row=0, column=1, padx=10, sticky="w")
rule_combobox = ttk.Combobox(root, values=msg_values, width=230,  font=("Helvetica", 11))
rule_combobox.grid(row=1, column=1, padx=10, pady=(0, 13), sticky="w")

# Enable the search functionality
rule_combobox['state'] = 'readonly'

# Create a Label widget for the selected rule title
rule_label = tk.Label(root, text="Selected rule:", font=("Helvetica", 10))
rule_label.grid(row=2, column=0, columnspan=3, padx=10, sticky="w")

# Create a Text widget to display the selected rule
rule_text = tk.Text(root, wrap=tk.WORD, width=400, height=15,  font=("Helvetica", 11))
rule_text.grid(row=3, column=0, columnspan=3, padx=10, pady=(0, 13))
rule_text.tag_configure("center", justify='center')
rule_text.config(state=tk.DISABLED)

# Create a Label widget for the content title
content_label = tk.Label(root, text="Content:", font=("Helvetica", 10))
content_label.grid(row=4, column=0, padx=10, sticky="w")

# Create a Text widget for the content_box
content_box = tk.Text(root, wrap=tk.WORD, width=180, height=12, font=("Helvetica", 11))
content_box.grid(row=5, column=0, padx=10, pady=(0, 10), sticky="w")
content_box.config(state=tk.DISABLED)

# Create a Label widget for the input payload title
input_label = tk.Label(root, text="Input payload:", font=("Helvetica", 10))
input_label.grid(row=6, column=0, columnspan=3, padx=10, sticky="w")

# Create an input field as a Text widget
input_text = tk.Text(root, wrap=tk.WORD, width=400, height=16,  font=("Helvetica", 11))
input_text.grid(row=7, column=0, columnspan=3, padx=10, pady=(0, 10))

# Scrollbar for rule_text
rule_text_scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=rule_text.yview)
rule_text_scrollbar.grid(row=3, column=3, sticky='ns')
rule_text.config(yscrollcommand=rule_text_scrollbar.set)

# Scrollbar for content_box
content_box_scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=content_box.yview)
content_box_scrollbar.grid(row=5, column=3, sticky='ns')
content_box.config(yscrollcommand=content_box_scrollbar.set)

# Create a Label widget for the nocase information
nocase_label = tk.Label(root, text="Nocase:", font=("Helvetica", 10))
nocase_label.grid(row=4, column=1, padx=7, sticky="w")

# Create a Text widget for the nocase information
nocase_box = tk.Text(root, wrap=tk.WORD, width=10, height=1, font=("Helvetica", 11))
nocase_box.grid(row=5, column=1, padx=10, pady=(0, 10), sticky="nw")
nocase_box.config(state=tk.DISABLED)

# Scrollbar for input_text
input_text_scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=input_text.yview)
input_text_scrollbar.grid(row=7, column=3, sticky='ns')
input_text.config(yscrollcommand=input_text_scrollbar.set)

# Configure row and column weights to make them resizable
root.grid_rowconfigure(3, weight=1)
root.grid_rowconfigure(5, weight=1)
root.grid_rowconfigure(7, weight=1)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_columnconfigure(2, weight=1)

# Bind functions to events
search_entry.bind('<KeyRelease>', lambda event: update_combobox_options(search_entry.get()))
rule_combobox.bind('<<ComboboxSelected>>', select_rule)

# Start the GUI event loop

root.mainloop()
