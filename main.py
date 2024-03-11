import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import webbrowser
import ctypes

ctypes.windll.shcore.SetProcessDpiAwareness(1)

content_list = []


class PatternMatcher:
    def __init__(self, pattern):
        self.pattern = pattern

    def match(self, text):
        return re.search(self.pattern, text)


class SuricataRuleParser:
    def __init__(self):
        self.pcre_pattern = r'pcre:\s*"([^"]+)"'

        self.keyword_pcre = re.compile(self.pcre_pattern)

    def extract_pcre(self, rule_text):
        pcre = self.keyword_pcre.findall(rule_text)
        return pcre


def hex_to_ascii(match):
    hex_string = match.group(1).replace("|", "")
    hex_values = hex_string.split()  # Split by spaces
    ascii_string = ""
    for hex_value in hex_values:
        try:
            char_code = int(hex_value, 16)
            if char_code == 0:
                ascii_string += " "  # Replace null character with a space
            else:
                ascii_string += chr(char_code)
        except ValueError:
            ascii_string += match.group(0)  # Return the original string if conversion fails
    return ascii_string


def get_content_in_ascii():
    input_text.tag_remove("highlight", "1.0", tk.END)
    content_box.delete("1.0", tk.END)
    input_text_content = input_text.get("1.0", tk.END).strip()
    selected_rule = rule_text.get("1.0", tk.END)
    rule_parts = re.split(r'\s*;\s*', selected_rule)
    output_list = []

    current_content = None
    current_properties = {}

    for part in rule_parts:
        if "content:" in part and "content:!" not in part:
            if current_content is not None:
                output_list.append({current_content: current_properties})
            match = re.search(r'content:\s*"([^"]+)"', part)
            if match:
                current_content = match.group(1)
                current_properties = {}
        else:
            if ":" in part:  # Check if the part contains a colon
                key, value = part.split(':', 1)  # Limit the split operation to one split
                current_properties[key.strip()] = value.strip() if value.strip() != 'None' else None
                if "reference" in part:
                    output_list.append({current_content: current_properties})
                    break
            else:
                # Skip parts that don't contain a colon
                continue

    results = []

    try:
        for sublist in output_list:
            for content, properties in sublist.items():
                # Construct the result string with properties
                result_str = (
                    f"{content}, distance: {properties.get('distance', 'None')}, "
                    f"offset: {properties.get('offset', 'None')}, "
                    f"within: {properties.get('within', 'None')}, "
                    f"depth: {properties.get('depth', 'None')}, "
                    f"nocase: {properties.get('nocase', 'False')}"
                )

                converted_text = re.sub(r'\|([0-9A-Fa-f ]+)*\|', hex_to_ascii, result_str)
                # Add colored text to the Text widget based on index
                index = 0
                for part in converted_text.split(','):
                    if index == 0:
                        content_box.insert(tk.END, part, "black")
                    elif index == 1:
                        content_box.insert(tk.END, part + ",", "blue")
                    elif index == 2:
                        content_box.insert(tk.END, part + ",", "red")
                    elif index == 3:
                        content_box.insert(tk.END, part + ",", "green")
                    elif index == 4:
                        content_box.insert(tk.END, part + ",", "orange")
                    else:
                        content_box.insert(tk.END, part, "violet")
                    index += 1

                # Define text colors
                content_box.tag_config("black", foreground="black")
                content_box.tag_config("blue", foreground="blue")
                content_box.tag_config("red", foreground="red")
                content_box.tag_config("green", foreground="green")
                content_box.tag_config("orange", foreground="orange")
                content_box.tag_config("violet", foreground="violet")

                results.append(converted_text)

            # Insert a newline after each sublist
            content_box.insert(tk.END, "\n", "black")

    except TypeError:
        pass


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

        pcre_values = suricata_parser.extract_pcre(selected_rule)

        pcre_text = ""
        if pcre_values:
            for pcre in pcre_values:
                pcre_text += f"{pcre}"

        pcre_box.config(state=tk.NORMAL)
        pcre_box.delete("1.0", tk.END)
        pcre_box.insert(tk.END, pcre_text)
        pcre_box.tag_add("center", "1.0", "end")
        pcre_box.config(state=tk.DISABLED)

        # Update the content box with the content extracted from the selected rule
        try:
            # Update the content box with the content extracted from the selected rule
            content_box.config(state=tk.NORMAL)
            content_box.delete("1.0", tk.END)
            content_box.insert(tk.END, get_content())  # Call get_content only once
            content_box.tag_add("center", "1.0", "end")
            content_box.config(state=tk.DISABLED)
        except:
            pass
        check_content()


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


def check_content(event=None):
    input_text.tag_remove("highlight", "1.0", tk.END)

    # Get the content from the input field
    input_text_content = input_text.get("1.0", tk.END).strip()

    # Get the selected rule text
    selected_rule = rule_text.get("1.0", tk.END)

    # Split the rule by semicolon
    rule_parts = re.split(r'\s*;\s*', selected_rule)

    # Initialize a list to store the output
    output_list = []

    # Initialize variables to store current content and properties
    current_content = None
    current_properties = []

    # Iterate through each part of the rule
    for part in rule_parts:
        # Check if the part contains "content"
        if "content:" in part and "content:!" not in part:
            # If there are accumulated properties and content is not None, add them to the output list
            if current_content is not None:
                output_list.append([current_content] + current_properties)
            # Extract content value for the new content
            match = re.search(r'content:\s*"([^"]+)"', part)
            if match:
                current_content = match.group(1)
                # Reset the properties list for the new content
                current_properties = []
        else:
            # Accumulate other properties for the current content
            current_properties.append(part)
            # Check if the current part contains "reference"
            if "reference" in part:
                # If "reference" is found, it's the last part for the current content
                # Add the current content and its properties to the output list
                output_list.append([current_content] + current_properties)
                # Break out of the loop after the first "reference"
                break

    # Removing element from list of lists
    cleaned_data = []
    for sublist in output_list:
        try:
            # Remove elements containing 'reference:'
            sublist = [element for element in sublist if 'reference:' not in element]

            # Find the index of the first occurrence of 'content:!'
            content_index = next((i for i, element in enumerate(sublist) if 'content:!' in element), None)

            # Append elements before 'content:!' to cleaned_data if content_index is found
            if content_index is not None:
                cleaned_data.append(sublist[:content_index])
            else:
                cleaned_data.append(sublist)
        except TypeError:
            # Handle the TypeError (NoneType is not iterable) gracefully
            pass

    # Check if cleaned_data is empty and return None in that case
    if not cleaned_data:
        cleaned_data = None

    try:
        for sublist in cleaned_data:
            # Check if the first element of the sublist contains hex values
            if '|' in sublist[0]:
                # Use a regular expression to find hex values and convert them
                sublist[0] = re.sub(r'\|([0-9A-Fa-f ]+)\|', hex_to_ascii, sublist[0])
    except TypeError:
        pass

    results = []
    try:
        for sublist in cleaned_data:
            result_sublist = [sublist[0]]  # Preserve the first element

            distance = None
            offset = None
            within = None
            depth = None
            nocase = False

            for item in sublist[1:]:
                if 'distance' in item:
                    distance = int(item.split(':')[-1])
                elif 'offset' in item:
                    offset = int(item.split(':')[-1])
                elif 'within' in item:
                    within = int(item.split(':')[-1])
                elif 'depth' in item:
                    depth = int(item.split(':')[-1])
                elif 'nocase' in item:
                    nocase = True

            result_sublist.extend([distance, offset, within, depth, nocase])
            results.append(result_sublist)
    except TypeError:
        pass

    for sublist in results:
        content = sublist[0]  # Extract content from the sublist
        distance, offset, within, depth, nocase = sublist[1:6]  # Extract other options

        if offset is None:
            offset = 0
        if depth is not None:
            text = input_text_content.find(content, offset, depth)
        else:
            text = input_text_content.find(content, offset)
        if text != -1:  # Check if the content is found in the input_text_content
            start_index = 0
            while True:
                start_index = int(start_index)  # Convert start_index to integer
                start_index = input_text_content.find(content, start_index)
                if start_index == -1:
                    break
                end_index = f"{start_index}+{len(content)}c"
                input_text.tag_add("highlight", f"{start_index + 1}c", f"{end_index + 1}c")
                start_index = f"{end_index}+1c"

                # Configure the tag to highlight text with a yellow background
                input_text.tag_configure("highlight", background="yellow")
        else:
            pass


#
def get_content(event=None):
    input_text.tag_remove("highlight", "1.0", tk.END)

    input_text_content = input_text.get("1.0", tk.END).strip()
    selected_rule = rule_text.get("1.0", tk.END)
    rule_parts = re.split(r'\s*;\s*', selected_rule)
    output_list = []

    current_content = None
    current_properties = {}

    for part in rule_parts:
        if "content:" in part and "content:!" not in part:
            if current_content is not None:
                output_list.append({current_content: current_properties})
            match = re.search(r'content:\s*"([^"]+)"', part)
            if match:
                current_content = match.group(1)
                current_properties = {}
        else:
            if ":" in part:  # Check if the part contains a colon
                key, value = part.split(':', 1)  # Limit the split operation to one split
                current_properties[key.strip()] = value.strip() if value.strip() != 'None' else None
                if "reference" in part:
                    output_list.append({current_content: current_properties})
                    break
            else:
                # Skip parts that don't contain a colon
                continue

    results = []

    try:
        for sublist in output_list:
            for content, properties in sublist.items():
                # Construct the result string with properties
                result_str = (
                    f"{content}, distance: {properties.get('distance', 'None')}, "
                    f"offset: {properties.get('offset', 'None')}, "
                    f"within: {properties.get('within', 'None')}, "
                    f"depth: {properties.get('depth', 'None')}, "
                    f"nocase: {properties.get('nocase', 'False')}"
                )

                # Add colored text to the Text widget based on index
                index = 0
                for part in result_str.split(','):
                    if index == 0:
                        content_box.insert(tk.END, part, "black")
                    elif index == 1:
                        content_box.insert(tk.END, part + ",", "blue")
                    elif index == 2:
                        content_box.insert(tk.END, part + ",", "red")
                    elif index == 3:
                        content_box.insert(tk.END, part + ",", "green")
                    elif index == 4:
                        content_box.insert(tk.END, part + ",", "orange")
                    else:
                        content_box.insert(tk.END, part, "violet")
                    index += 1

                # Define text colors
                content_box.tag_config("black", foreground="black")
                content_box.tag_config("blue", foreground="blue")
                content_box.tag_config("red", foreground="red")
                content_box.tag_config("green", foreground="green")
                content_box.tag_config("orange", foreground="orange")
                content_box.tag_config("violet", foreground="violet")

                results.append(result_str)

            # Insert a newline after each sublist
            content_box.insert(tk.END, "\n","black")

    except TypeError:
        pass

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


def convert_ascii_button_action():
    select_rule(None)
    check_content()


def perform_search():
    update_combobox_options(search_entry.get())


root = tk.Tk()
root.title("SURICATER")
root.iconbitmap('assets/img/logo.ico')
root.option_add("*TCombobox*Listbox.font", "Helevetica 10")

# Set the initial window size
root.minsize(1100, 900)
root.geometry(f"1300x900")
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

# Create a Combobox to select the "msg" option
rules_label = tk.Label(root, text="Rules:", font=("Helvetica", 10))
rules_label.grid(row=0, column=1, padx=10, sticky="w")

rule_combobox = ttk.Combobox(root, values=msg_values, width=100, font=("Helvetica", 11))
rule_combobox.grid(row=1, column=1, columnspan=8, padx=10, pady=(0, 10), sticky="w")

# Enable the search functionality
rule_combobox['state'] = 'readonly'

# Create a search box Entry widget with a placeholder
search_entry = tk.Entry(root, width=40, font=("Helvetica", 11))
search_entry.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="w")

# search_button
search_button = ttk.Button(root, text="Search", command=lambda: update_combobox_options(search_entry.get()), width=10)
search_button.grid(row=1, column=0, padx=5, pady=(0, 10), sticky="e")

# Bind <Return> event to search_entry
search_entry.bind('<Return>', lambda event: perform_search())

# Create a Label widget for the selected rule title
rule_label = tk.Label(root, text="Selected rule:", font=("Helvetica", 10))
rule_label.grid(row=2, column=0, columnspan=9, padx=10, sticky="sw")

# Create a Text widget to display the selected rule
rule_text = tk.Text(root, wrap=tk.WORD, width=400, height=9, font=("Helvetica", 12))
rule_text.grid(row=3, column=0, columnspan=9, padx=10, pady=(0, 5))
rule_text.tag_configure("center", justify='center')
rule_text.config(state=tk.DISABLED)

# Scrollbar for rule_text
rule_text_scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=rule_text.yview)
rule_text_scrollbar.grid(row=3, column=9, sticky='ns')
rule_text.config(yscrollcommand=rule_text_scrollbar.set)

# button from hex
convert_content_button = ttk.Button(root, text="To ASCII", command=get_content_in_ascii, width=17)
convert_content_button.grid(row=6, column=0, pady=5, sticky="e")  # Adjust padx as needed

# button to hex
convert_ascii_button = ttk.Button(root, text="Refresh", command=convert_ascii_button_action, width=17)
convert_ascii_button.grid(row=6, column=1, padx=5, sticky="e")  # Adjust padx as needed

# Create a Label widget for the content title
content_label = tk.Label(root, text="Content:", font=("Helvetica", 10))
content_label.grid(row=4, column=0, columnspan=9, padx=10, pady=(0, 5), sticky="sw")

# Create a Text widget for the content_box
content_box = tk.Text(root, wrap=tk.WORD, width=400, height=5, font=("Helvetica", 11))
content_box.grid(row=5, column=0, columnspan=9, padx=10, pady=(0, 5), sticky="w")
content_box.config(state=tk.DISABLED)

# Scrollbar for content_box
content_box_scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=content_box.yview)
content_box_scrollbar.grid(row=5, column=9, sticky='ns')
content_box.config(yscrollcommand=content_box_scrollbar.set)

# Create a Label widget for the pcre title
pcre_label = tk.Label(root, text="Pcre:", font=("Helvetica", 10))
pcre_label.grid(row=6, column=0, columnspan=9, padx=10, pady=(10, 5), sticky="sw")

# Create a Text widget for the pcre_box
pcre_box = tk.Text(root, wrap=tk.WORD, width=400, height=2, font=("Helvetica", 11))
pcre_box.grid(row=7, column=0, columnspan=9, padx=10, pady=(0, 10), sticky="w")
pcre_box.config(state=tk.DISABLED)

# Scrollbar for pcre_box
pcre_box_scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=pcre_box.yview)
pcre_box_scrollbar.grid(row=7, column=9, sticky='ns')
pcre_box.config(yscrollcommand=pcre_box_scrollbar.set)

# Create a Label widget for the input payload title
input_label = tk.Label(root, text="Input payload:", font=("Helvetica", 10))
input_label.grid(row=8, column=0, columnspan=8, padx=10, sticky="sw")

# Create an input field as a Text widget
input_text = tk.Text(root, wrap=tk.WORD, width=400, height=8, font=("Helvetica", 11))
input_text.grid(row=9, column=0, columnspan=9, padx=10)

# Scrollbar for input_text
input_text_scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=input_text.yview)
input_text_scrollbar.grid(row=9, column=9, sticky='ns')
input_text.config(yscrollcommand=input_text_scrollbar.set)

# Configure row and column weights to make them resizable
root.grid_rowconfigure(3, weight=1)
root.grid_rowconfigure(4, weight=1)
root.grid_rowconfigure(9, weight=1)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_columnconfigure(2, weight=1)
root.grid_columnconfigure(3, weight=1)
root.grid_columnconfigure(4, weight=1)
root.grid_columnconfigure(5, weight=1)
root.grid_columnconfigure(6, weight=1)
root.grid_columnconfigure(7, weight=1)
root.grid_columnconfigure(8, weight=1)
# Bind functions to events

rule_combobox.bind('<<ComboboxSelected>>', select_rule)
input_text.bind('<KeyRelease>', check_content)
# Start the GUI event loop
root.mainloop()
