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
        self.keyword_content = re.compile(r'content:\s*"([^"]+)"')
        self.keyword_nocase = re.compile(r'\bnocase\b')
        self.keyword_startwith = re.compile(r'\bstartwith\b')
        self.keyword_endwith = re.compile(r'\bendwith\b')
        self.keyword_depth = re.compile(r'\bdepth:\s*(\d+)\b')
        self.keyword_offset = re.compile(r'\boffset:\s*(\d+)\b')
        self.keyword_distance = re.compile(r'\bdistance:\s*(-?\d+)\b')
        self.keyword_within = re.compile(r'\bwithin:\s*(\d+)\b')
        self.keyword_isdataat = re.compile(r'\bisdataat:\s*(!?)(\d+)(?:,(\w+))?(\b|;|\s)')
        self.keyword_pcre = re.compile(r'pcre:\s*"([^"]+)"')

    def extract_content(self, rule_text):
        matches = self.keyword_content.findall(rule_text)
        return matches

    def has_nocase(self, rule_text):
        return bool(self.keyword_nocase.search(rule_text))

    def has_startwith(self, rule_text):
        return bool(self.keyword_startwith.search(rule_text))

    def has_endwith(self, rule_text):
        return bool(self.keyword_endwith.search(rule_text))

    def get_all_depth(self, rule_text):
        depth_matches = self.keyword_depth.finditer(rule_text)
        return [int(match.group(1)) for match in depth_matches] if depth_matches else []

    def get_all_offset(self, rule_text):
        offset_matches = self.keyword_offset.finditer(rule_text)
        return [int(match.group(1)) for match in offset_matches] if offset_matches else []

    def get_all_distance(self, rule_text):
        distance_matches = self.keyword_distance.finditer(rule_text)
        return [int(match.group(1)) for match in distance_matches] if distance_matches else []

    def get_all_within(self, rule_text):
        within_matches = self.keyword_within.finditer(rule_text)
        return [int(match.group(1)) for match in within_matches] if within_matches else []

    def get_all_isdataat(self, rule_text):
        isdataat_matches = self.keyword_isdataat.finditer(rule_text)
        return [f"{match.group(1)}{match.group(2)}, {match.group(3)}" if match.group(
            3) else f"{match.group(1)}{match.group(2)}" for match in isdataat_matches] if isdataat_matches else []

    def extract_pcre(self, rule_text):
        pcre = self.keyword_pcre.findall(rule_text)
        return pcre

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
        startwith_info = "True" if suricata_parser.has_startwith(selected_rule) else "False"
        endwith_info = "True" if suricata_parser.has_endwith(selected_rule) else "False"
        depth_values = suricata_parser.get_all_depth(selected_rule)
        offset_values = suricata_parser.get_all_offset(selected_rule)
        distance_values = suricata_parser.get_all_distance(selected_rule)
        within_values = suricata_parser.get_all_within(selected_rule)
        isdataat_values = suricata_parser.get_all_isdataat(selected_rule)
        pcre_values = suricata_parser.extract_pcre(selected_rule)

        content_text = ""
        if payload_keywords:
            for keyword in payload_keywords:
                content_text += f"{keyword}\n"

        pcre_text = ""
        if pcre_values:
            for pcre in pcre_values:
                pcre_text += f"{pcre}\n"

        content_box.config(state=tk.NORMAL)
        content_box.delete("1.0", tk.END)
        content_box.insert(tk.END, content_text)
        content_box.tag_add("center", "1.0", "end")
        content_box.config(state=tk.DISABLED)

        # Update the nocase information
        nocase_box.config(state=tk.NORMAL)
        nocase_box.delete("1.0", tk.END)
        nocase_box.insert(tk.END, nocase_info)
        nocase_box.tag_add("center", "1.0", "end")
        nocase_box.config(state=tk.DISABLED)

        startwith_box.config(state=tk.NORMAL)
        startwith_box.delete("1.0", tk.END)
        startwith_box.insert(tk.END, startwith_info)
        startwith_box.tag_add("center", "1.0", "end")
        startwith_box.config(state=tk.DISABLED)

        endwith_box.config(state=tk.NORMAL)
        endwith_box.delete("1.0", tk.END)
        endwith_box.insert(tk.END, endwith_info)
        endwith_box.tag_add("center", "1.0", "end")
        endwith_box.config(state=tk.DISABLED)

        depth_box.config(state=tk.NORMAL)
        depth_box.delete("1.0", tk.END)
        depth_box.insert(tk.END, "; ".join(map(str, depth_values)))
        depth_box.tag_add("center", "1.0", "end")
        depth_box.config(state=tk.DISABLED)

        offset_box.config(state=tk.NORMAL)
        offset_box.delete("1.0", tk.END)
        offset_box.insert(tk.END, "; ".join(map(str, offset_values)))
        offset_box.tag_add("center", "1.0", "end")
        offset_box.config(state=tk.DISABLED)

        distance_box.config(state=tk.NORMAL)
        distance_box.delete("1.0", tk.END)
        distance_box.insert(tk.END, "; ".join(map(str, distance_values)))
        distance_box.tag_add("center", "1.0", "end")
        distance_box.config(state=tk.DISABLED)

        within_box.config(state=tk.NORMAL)
        within_box.delete("1.0", tk.END)
        within_box.insert(tk.END, "; ".join(map(str, within_values)))
        within_box.tag_add("center", "1.0", "end")
        within_box.config(state=tk.DISABLED)

        isdataat_box.config(state=tk.NORMAL)
        isdataat_box.delete("1.0", tk.END)
        isdataat_box.insert(tk.END, "; ".join(map(str, isdataat_values)))
        isdataat_box.tag_add("center", "1.0", "end")
        isdataat_box.config(state=tk.DISABLED)

        pcre_box.config(state=tk.NORMAL)
        pcre_box.delete("1.0", tk.END)
        pcre_box.insert(tk.END, pcre_text)
        pcre_box.tag_add("center", "1.0", "end")
        pcre_box.config(state=tk.DISABLED)

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
rule_combobox = ttk.Combobox(root, values=msg_values, width=230, font=("Helvetica", 11))
rule_combobox.grid(row=1, column=1, padx=10, pady=(0, 13), sticky="w")

# Enable the search functionality
rule_combobox['state'] = 'readonly'

# Create a Label widget for the selected rule title
rule_label = tk.Label(root, text="Selected rule:", font=("Helvetica", 10))
rule_label.grid(row=2, column=0, columnspan=3, padx=10, sticky="w")

# Create a Text widget to display the selected rule
rule_text = tk.Text(root, wrap=tk.WORD, width=400, height=15, font=("Helvetica", 12))
rule_text.grid(row=3, column=0, columnspan=3, padx=10, pady=(0, 13))
rule_text.tag_configure("center", justify='center')
rule_text.config(state=tk.DISABLED)

# Create a Label widget for the content title
content_label = tk.Label(root, text="Content:", font=("Helvetica", 10))
content_label.grid(row=4, column=0, padx=10, sticky="w")

# Create a Text widget for the content_box
content_box = tk.Text(root, wrap=tk.WORD, width=180, height=18, font=("Helvetica", 12))
content_box.grid(row=5, column=0, padx=10, pady=(0, 10), sticky="w")
content_box.config(state=tk.DISABLED)

# Scrollbar for rule_text
rule_text_scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=rule_text.yview)
rule_text_scrollbar.grid(row=3, column=3, sticky='ns')
rule_text.config(yscrollcommand=rule_text_scrollbar.set)

# Scrollbar for content_box
content_box_scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=content_box.yview)
content_box_scrollbar.grid(row=5, column=0, sticky='e ns')
content_box.config(yscrollcommand=content_box_scrollbar.set)

# Create a Label widget for the nocase information
nocase_label = tk.Label(root, text="Nocase:", font=("Helvetica", 10))
nocase_label.grid(row=5, column=1, padx=55, sticky="nw")

# Create a Text widget for the nocase information
nocase_box = tk.Text(root, wrap=tk.WORD, width=15, height=1, font=("Helvetica", 11))
nocase_box.grid(row=5, column=1, pady=30, sticky="nw")
nocase_box.tag_configure("center", justify='center')
nocase_box.config(state=tk.DISABLED)

# Create a Label widget for the nocase information
# Create a Label widget for the startwith information
startwith_label = tk.Label(root, text="Startwith:", font=("Helvetica", 10))
startwith_label.grid(row=5, column=1, sticky="n")

# Create a Text widget for the startwith information
startwith_box = tk.Text(root, wrap=tk.WORD, width=15, height=1, font=("Helvetica", 11))
startwith_box.grid(row=5, column=1, pady=30, sticky="n")
startwith_box.tag_configure("center", justify='center')
startwith_box.config(state=tk.DISABLED)

# Create a Label widget for the endwith information
endwith_label = tk.Label(root, text="Endwith:", font=("Helvetica", 10))
endwith_label.grid(row=5, column=1, padx=60, sticky="ne")

# Create a Text widget for the endwith information
endwith_box = tk.Text(root, wrap=tk.WORD, width=15, height=1, font=("Helvetica", 11))
endwith_box.grid(row=5, column=1, pady=30, padx=10, sticky="ne")
endwith_box.tag_configure("center", justify='center')
endwith_box.config(state=tk.DISABLED)

# Create a Label widget for the depth information
depth_label = tk.Label(root, text="Depth:", font=("Helvetica", 10))
depth_label.grid(row=5, column=1, sticky="w", padx=60)  # Set row to 4 (or any appropriate row index)

# Create a Text widget for the depth information
depth_box = tk.Text(root, wrap=tk.WORD, width=15, height=1, font=("Helvetica", 11))
depth_box.grid(row=5, column=1, sticky="w", pady=(60, 0))  # Set columnspan to 2 to make the box span two columns
depth_box.tag_configure("center", justify='center')
depth_box.config(state=tk.DISABLED)

# Create a Label widget for the offset information
offset_label = tk.Label(root, text="Offset:", font=("Helvetica", 10))
offset_label.grid(row=5, column=1, padx=60)  # Set row to 4 (or any appropriate row index)

# Create a Text widget for the offset information
offset_box = tk.Text(root, wrap=tk.WORD, width=15, height=1, font=("Helvetica", 11))
offset_box.grid(row=5, column=1, pady=(60, 0))  # Set columnspan to 2 to make the box span two columns
offset_box.tag_configure("center", justify='center')
offset_box.config(state=tk.DISABLED)

# Create a Label widget for the distance information
distance_label = tk.Label(root, text="Distance:", font=("Helvetica", 10))
distance_label.grid(row=5, column=1, sticky="e", padx=58)  # Set row to 4 (or any appropriate row index)

# Create a Text widget for the distance information
distance_box = tk.Text(root, wrap=tk.WORD, width=15, height=1, font=("Helvetica", 11))
distance_box.grid(row=5, column=1, sticky="e", pady=(60, 0),
                  padx=10)  # Set columnspan to 2 to make the box span two columns
distance_box.tag_configure("center", justify='center')
distance_box.config(state=tk.DISABLED)

# Create a Label widget for the within information
within_label = tk.Label(root, text="Within:", font=("Helvetica", 10))
within_label.grid(row=5, column=1, sticky="sw", padx=60, pady=30)  # Set row to 4 (or any appropriate row index)

# Create a Text widget for the within information
within_box = tk.Text(root, wrap=tk.WORD, width=15, height=1, font=("Helvetica", 11))
within_box.grid(row=5, column=1, sticky="sw")  # Set columnspan to 2 to make the box span two columns
within_box.tag_configure("center", justify='center')
within_box.config(state=tk.DISABLED)

# Create a Label widget for the isdataat information
isdataat_label = tk.Label(root, text="Isdataat:", font=("Helvetica", 10))
isdataat_label.grid(row=5, column=1, sticky="s", padx=60, pady=30)  # Set row to 4 (or any appropriate row index)

# Create a Text widget for the isdataat information
isdataat_box = tk.Text(root, wrap=tk.WORD, width=15, height=1, font=("Helvetica", 11))
isdataat_box.grid(row=5, column=1, sticky="s")  # Set columnspan to 2 to make the box span two columns
isdataat_box.tag_configure("center", justify='center')
isdataat_box.config(state=tk.DISABLED)

# Create a Label widget for the pcre title
pcre_label = tk.Label(root, text="Pcre:", font=("Helvetica", 10))
pcre_label.grid(row=6, column=0, columnspan=3, padx=10, sticky="w")

# Create a Text widget for the content_box
pcre_box = tk.Text(root, wrap=tk.WORD, width=400, height=2, font=("Helvetica", 11))
pcre_box.grid(row=7, column=0, columnspan=3, padx=10, pady=(0, 10))
pcre_box.config(state=tk.DISABLED)

# Scrollbar for pcre
pcre_box_scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=pcre_box.yview)
pcre_box_scrollbar.grid(row=7, column=3, sticky='ns')
pcre_box.config(yscrollcommand=pcre_box_scrollbar.set)

# Create a Label widget for the input payload title
input_label = tk.Label(root, text="Input payload:", font=("Helvetica", 10))
input_label.grid(row=8, column=0, columnspan=3, padx=10, sticky="w")

# Create an input field as a Text widget
input_text = tk.Text(root, wrap=tk.WORD, width=400, height=16, font=("Helvetica", 11))
input_text.grid(row=9, column=0, columnspan=3, padx=10, pady=(0, 10))

# Scrollbar for input_text
input_text_scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=input_text.yview)
input_text_scrollbar.grid(row=9, column=3, sticky='ns')
input_text.config(yscrollcommand=input_text_scrollbar.set)

# Configure row and column weights to make them resizable
root.grid_rowconfigure(3, weight=1)
root.grid_rowconfigure(5, weight=1)
root.grid_rowconfigure(9, weight=1)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_columnconfigure(2, weight=1)

# Bind functions to events
search_entry.bind('<KeyRelease>', lambda event: update_combobox_options(search_entry.get()))
rule_combobox.bind('<<ComboboxSelected>>', select_rule)

# Start the GUI event loop
root.mainloop()
