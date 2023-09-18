import tkinter as tk
from tkinter import ttk
from tkinter import filedialog  # Import the file dialog module
import re
import webbrowser  # Import the webrowser module

# Function to handle rule selection
def select_rule():
    selected_rule_index = rule_combobox.current()
    if selected_rule_index != -1 and selected_rule_index < len(filtered_rules):
        selected_rule = filtered_rules[selected_rule_index]
        rule_text.config(state=tk.NORMAL)  # Make the Text widget editable
        rule_text.delete("1.0", tk.END)  # Clear the Text widget
        rule_text.insert(tk.END, selected_rule)  # Insert the selected rule
        rule_text.tag_configure("center", justify='center')

        # Adjust the height of the Text widget based on the number of lines needed
        content = rule_text.get("1.0", "end")
        num_lines = len(content.split('\n'))
        width = rule_text.winfo_width()
        max_chars_per_line = width // 9
        num_lines_needed = len(content) // max_chars_per_line + 1
        rule_text.config(height=num_lines_needed)

        # Scroll to the top
        rule_text.yview_moveto(0.0)

        rule_text.tag_add("center", "1.0", "end")
        rule_text.config(state=tk.DISABLED)  # Make the Text widget read-only
        print("Selected Rule:", selected_rule)

# Function to clear the search box when clicked
def clear_search(event):
    if search_entry.get() == "Search":
        search_entry.delete(0, tk.END)
        update_combobox_options("")  # Reset the ComboBox to show all rules

# Function to update ComboBox options based on the search text
def update_combobox_options(search_text):
    matching_msgs = []
    matching_rules = []  # Store the rules that match the search criteria
    for i, rule in enumerate(rules):
        if search_text.lower() in rule.lower():
            match = re.search(r'msg:"([^"]+)"', rule)
            if match:
                matching_msgs.append(match.group(1))
                matching_rules.append(rules[i])  # Add matching rule to the list
        elif search_text.isdigit():
            # Check if the search text is a number and if it exists in the rule
            if search_text in rule:
                match = re.search(r'msg:"([^"]+)"', rule)
                if match:
                    matching_msgs.append(match.group(1))
                    matching_rules.append(rules[i])  # Add matching rule to the list

    rule_combobox['values'] = matching_msgs
    global filtered_rules  # Define a global variable to store filtered rules
    filtered_rules = matching_rules  # Update filtered_rules with matching rules

# Function to handle "Choose" menu item
def choose_file_action():
    global filtered_rules  # Use the global filtered_rules
    file_path = filedialog.askopenfilename(title="Choose a File")
    if file_path:
        with open(file_path, 'r') as file:
            rules.clear()
            msg_values.clear()
            for line in file:
                if re.search(r'\bsid\b', line):
                    # Remove leading '#' if it exists
                    cleaned_line = line.lstrip('#').strip()
                    rules.append(cleaned_line)
                    match = re.search(r'msg:"([^"]+)"', cleaned_line)
                    if match:
                        msg_values.append(match.group(1))
            filtered_rules = rules.copy()  # Update the global filtered_rules
            rule_combobox['values'] = msg_values

def open_documentation():
    webbrowser.open('suricata-latest\index.html')
# Create the main window
root = tk.Tk()
root.title("Suricater")

# Set the initial window size
root.geometry("800x500")

# Create a menu bar
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

# Create a File menu
signatures_menu = tk.Menu(menu_bar, tearoff=0)
help_menu = tk.Menu(menu_bar, tearoff=0)

menu_bar.add_cascade(label="Signatures", menu=signatures_menu)
menu_bar.add_cascade(label="Help", menu=help_menu)

# Add items to the File menu
signatures_menu.add_command(label="Choose", command=choose_file_action)  # Added command
signatures_menu.add_command(label="Create")
help_menu.add_command(label="Documentation", command=open_documentation)
help_menu.add_command(label="Info")

# Initialize rules and msg_values
rules = []
msg_values = []

# Store the original unfiltered rules
filtered_rules = rules.copy()

# Create a frame to hold the search elements
search_frame = tk.Frame(root)
search_frame.grid(row=0, column=0, padx=10, pady=10)

# Create a search box Entry widget with a placeholder
search_entry = tk.Entry(search_frame, width=30)
search_entry.insert(0, "Search")  # Placeholder text
search_entry.pack(side=tk.LEFT, padx=5)

# Create a Combobox to select the "msg" option
rule_combobox = ttk.Combobox(root, values=msg_values, width=70)
rule_combobox.grid(row=0, column=1, padx=10, pady=10)  # Use grid layout

# Enable the search functionality
rule_combobox['state'] = 'readonly'

# Create a button to select the rule and place it next to the Combobox
select_button = tk.Button(root, text="Select Rule", command=select_rule)
select_button.grid(row=0, column=2, padx=20, pady=10)  # Use grid layout

# Create a Text widget to display the selected rule
rule_text = tk.Text(root, wrap=tk.WORD, width=85, height=20)
rule_text.grid(row=1, column=0, columnspan=3, padx=10, pady=10)
rule_text.tag_configure("center", justify='center')
rule_text.config(state=tk.DISABLED)  # Make the Text widget read-only

# Bind a function to update ComboBox options when typing in the search box
search_entry.bind('<KeyRelease>', lambda event: update_combobox_options(search_entry.get()))

# Bind a function to clear the search box when clicked
search_entry.bind('<Button-1>', clear_search)

# Start the GUI event loop
root.mainloop()