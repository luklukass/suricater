import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font
import re
import webbrowser
import ctypes

ctypes.windll.shcore.SetProcessDpiAwareness(1)

sid_pattern = re.compile(r'\bsid\b')
msg_pattern = re.compile(r'msg:"([^"]*)"')

content_list = []

class PatternMatcher:
    def __init__(self, pattern):
        self.pattern = pattern

    def match(self, text):
        return re.search(self.pattern, text)

    def match_all(self, text):
        return re.finditer(self.pattern, text)

class SuricataRuleParser:
    def __init__(self):
        self.pcre_pattern = r'pcre:\s*"((?:\\.|[^"\\])*)"'
        self.keyword_pcre = re.compile(self.pcre_pattern)

    def extract_pcre(self, rule_text):
        pcre = self.keyword_pcre.findall(rule_text)
        return [p.replace('\\"', '"') for p in pcre]

def hex_to_ascii(match):
    hex_string = match.group(1).replace("|", "")
    hex_values = hex_string.split()
    ascii_string = ""
    for hex_value in hex_values:
        try:
            char_code = int(hex_value, 16)
            ascii_string += chr(char_code)
        except ValueError:
            ascii_string += match.group(0)
    return ascii_string


def convert_hex_to_ascii(text):
    return re.sub(r'\|([0-9A-Fa-f ]+)\|', hex_to_ascii, text)


def cleanup_suricata_value(value):
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value.replace('\\"', '"')


def split_rule_options(rule_text):
    start = rule_text.find('(')
    end = rule_text.rfind(')')
    if start == -1 or end == -1 or end <= start:
        return []
    body = rule_text[start+1:end]
    options = []
    current = []
    in_quote = False
    escape = False

    for ch in body:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == '\\':
            current.append(ch)
            escape = True
            continue
        if ch == '"':
            in_quote = not in_quote
            current.append(ch)
            continue
        if ch == ';' and not in_quote:
            option = ''.join(current).strip()
            if option:
                options.append(option)
            current = []
            continue
        current.append(ch)

    last_option = ''.join(current).strip()
    if last_option:
        options.append(last_option)
    return options


def decode_suricata_string(value):
    decoded = cleanup_suricata_value(value)
    decoded = re.sub(r'\\x([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), decoded)
    return decoded


def parse_suricata_pcre(raw_pattern):
    pcre = raw_pattern.strip()
    if len(pcre) >= 2 and pcre[0] == '/' and '/' in pcre[1:]:
        end = pcre.rfind('/')
        pattern = pcre[1:end]
        flags = pcre[end+1:]
        re_flags = 0
        if 'i' in flags:
            re_flags |= re.IGNORECASE
        if 'm' in flags:
            re_flags |= re.MULTILINE
        if 's' in flags:
            re_flags |= re.DOTALL
        if 'x' in flags:
            re_flags |= re.VERBOSE
        return pattern, re_flags
    return pcre, 0


def decode_payload_text(payload):
    if not payload:
        return payload
    return re.sub(r'\\x([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), payload)


def parse_rule_threshold(rule_text):
    threshold_match = re.search(r'threshold:\s*([^;]+)', rule_text)
    if not threshold_match:
        return {}

    threshold_str = threshold_match.group(1)
    threshold = {}
    for part in threshold_str.split(','):
        part = part.strip()
        if not part:
            continue
        match = re.match(r'(\w+)\s*[: ]\s*(.+)', part)
        if match:
            threshold[match.group(1)] = match.group(2).strip()
    return threshold


def parse_rule_isdataat(rule_text):
    isdataat = []
    for opt in split_rule_options(rule_text):
        cleaned = opt.strip()
        if cleaned.startswith('isdataat:'):
            params = [p.strip() for p in cleaned.split(':', 1)[1].split(',') if p.strip()]
            if not params:
                continue
            count = int(params[0]) if params[0].isdigit() else None
            relative = 'relative' in [p.lower() for p in params[1:]]
            isdataat.append({'count': count, 'relative': relative})
    return isdataat


def parse_rule_metadata(rule_text):
    metadata = {
        'classtype': None,
        'flow': [],
        'flowbits': [],
        'fast_pattern': None,
        'tag': [],
        'priority': None,
        'metadata': None,
        'reference': [],
        'other': {},
    }

    for opt in split_rule_options(rule_text):
        cleaned = opt.strip()
        if not cleaned:
            continue
        if cleaned.startswith(('content:', 'content:!', 'rawbytes:', 'pcre:', 'byte_test:', 'isdataat:', 'threshold:')):
            continue

        if ':' not in cleaned:
            continue

        key, value = cleaned.split(':', 1)
        key = key.strip().lower()
        value = cleanup_suricata_value(value)

        if key == 'classtype':
            metadata['classtype'] = value
        elif key == 'flow':
            metadata['flow'] = [p.strip() for p in re.split(r'[ ,]+', value) if p.strip()]
        elif key == 'flowbits':
            metadata['flowbits'] = [p.strip() for p in re.split(r'[ ,]+', value) if p.strip()]
        elif key == 'fast_pattern':
            metadata['fast_pattern'] = value
        elif key == 'tag':
            metadata['tag'].append(value)
        elif key == 'priority':
            metadata['priority'] = value
        elif key == 'metadata':
            metadata['metadata'] = value
        elif key == 'reference':
            metadata['reference'].append(value)
        else:
            metadata['other'][key] = value

    return metadata


def parse_int_value(value_text):
    value_text = value_text.strip()
    if not value_text:
        return None
    try:
        if value_text.startswith('0x') or value_text.startswith('0X'):
            return int(value_text, 16)
        return int(value_text, 10)
    except ValueError:
        return None


def parse_rule_byte_tests(rule_text):
    tests = []
    for opt in split_rule_options(rule_text):
        cleaned = opt.strip()
        if cleaned.startswith('byte_test:'):
            params = [p.strip() for p in cleaned.split(':', 1)[1].split(',') if p.strip()]
            if len(params) < 4:
                continue
            size = parse_int_value(params[0])
            operator = params[1].lower()
            value = parse_int_value(params[2])
            offset = parse_int_value(params[3])
            options = [p.lower() for p in params[4:]]
            relative = 'relative' in options
            endian = 'little' if 'little' in options else 'big'
            signed = 'signed' in options
            tests.append({
                'size': size,
                'operator': operator,
                'value': value,
                'offset': offset,
                'relative': relative,
                'endian': endian,
                'signed': signed,
            })
    return tests


def parse_rule_contents(rule_text):
    options = split_rule_options(rule_text)
    content_infos = []
    current_item = None

    for opt in options:
        cleaned = opt.strip()
        if not cleaned:
            continue

        if cleaned.startswith('content:!'):
            if current_item is not None:
                content_infos.append(current_item)
            match = re.match(r'content:!\s*"((?:\\.|[^"\\])*)"', cleaned)
            if match:
                content_value = match.group(1)
                current_item = {
                    'content': cleanup_suricata_value(f'"{content_value}"'),
                    'properties': {},
                    'negated': True,
                }
            else:
                current_item = {
                    'content': cleanup_suricata_value(cleaned.split(':!', 1)[1]),
                    'properties': {},
                    'negated': True,
                }
            continue

        if cleaned.startswith('rawbytes:'):
            if current_item is not None:
                content_infos.append(current_item)
            match = re.match(r'rawbytes:\s*"((?:\\.|[^"\\])*)"', cleaned)
            if match:
                raw_value = match.group(1)
                current_item = {'content': cleanup_suricata_value(f'"{raw_value}"'), 'properties': {'rawbytes': True}, 'negated': False}
            else:
                current_item = {'content': cleanup_suricata_value(cleaned.split(':', 1)[1]), 'properties': {'rawbytes': True}, 'negated': False}
            continue

        if cleaned.startswith('content:'):
            if current_item is not None:
                content_infos.append(current_item)
            match = re.match(r'content:\s*"((?:\\.|[^"\\])*)"', cleaned)
            if match:
                content_value = match.group(1)
                current_item = {'content': cleanup_suricata_value(f'"{content_value}"'), 'properties': {}, 'negated': False}
            else:
                current_item = {'content': cleanup_suricata_value(cleaned.split(':', 1)[1]), 'properties': {}, 'negated': False}
            continue

        if current_item is None:
            continue

        if cleaned == 'nocase':
            current_item['properties']['nocase'] = True
            continue

        if ':' in cleaned:
            key, value = cleaned.split(':', 1)
            key = key.strip()
            value = cleanup_suricata_value(value)
            current_item['properties'][key] = value
            if key == 'reference':
                content_infos.append(current_item)
                current_item = None
            continue

    if current_item is not None:
        content_infos.append(current_item)

    return content_infos


def format_content_item(content_item):
    content = content_item['content']
    properties = content_item['properties']
    negated = content_item.get('negated', False)
    rawbytes = properties.get('rawbytes', False)
    return (
        f"{content}, negated: {negated}, rawbytes: {rawbytes}, distance: {properties.get('distance', 'None')}, "
        f"offset: {properties.get('offset', 'None')}, "
        f"within: {properties.get('within', 'None')}, "
        f"depth: {properties.get('depth', 'None')}, "
        f"nocase: {properties.get('nocase', False)}"
    )


def find_content_match(payload, content_item, search_start, search_end):
    pattern = decode_suricata_string(convert_hex_to_ascii(content_item['content']))
    if pattern == '':
        return None

    flags = re.IGNORECASE if content_item['properties'].get('nocase') else 0
    try:
        regex = re.compile(re.escape(pattern), flags)
    except re.error:
        return None

    segment = payload[search_start:search_end]
    match = regex.search(segment)
    if not match:
        return None

    return search_start + match.start(), search_start + match.end()


def match_rule_contents(payload, content_infos):
    matches = []
    last_end = 0

    for index, item in enumerate(content_infos):
        properties = item['properties']
        if item.get('negated'):
            negated_text = convert_hex_to_ascii(item['content'])
            flags = re.IGNORECASE if properties.get('nocase') else 0
            if re.search(re.escape(negated_text), payload, flags):
                return False, []
            continue

        offset = int(properties.get('offset', 0)) if properties.get('offset') and properties.get('offset').isdigit() else None
        depth = int(properties.get('depth')) if properties.get('depth') and properties.get('depth').isdigit() else None
        distance = int(properties.get('distance')) if properties.get('distance') and properties.get('distance').isdigit() else 0
        within = int(properties.get('within')) if properties.get('within') and properties.get('within').isdigit() else None

        if index == 0:
            search_start = offset if offset is not None else 0
            search_end = len(payload)
            if depth is not None:
                search_end = min(search_start + depth, len(payload))
        else:
            search_start = last_end + distance
            search_end = len(payload)
            if within is not None:
                search_end = min(search_start + within, len(payload))
            elif depth is not None:
                search_end = min(search_start + depth, len(payload))

        if search_start > len(payload) or search_start < 0:
            return False, []

        match_span = find_content_match(payload, item, search_start, search_end)
        if not match_span:
            return False, []

        matches.append({'start': match_span[0], 'end': match_span[1], 'item': item})
        last_end = match_span[1]

    return True, matches


def match_rule_pcre(payload, pcre_values):
    matches = []
    invalid = []
    for raw_pattern in pcre_values:
        pattern, flags = parse_suricata_pcre(raw_pattern)
        try:
            regex = re.compile(pattern, flags)
            for match in regex.finditer(payload):
                matches.append({'start': match.start(), 'end': match.end(), 'pattern': raw_pattern})
        except re.error:
            invalid.append(raw_pattern)
    return matches, invalid


def evaluate_byte_test(payload, test, content_matches):
    payload_bytes = payload.encode('latin-1', errors='ignore')
    if test['size'] is None or test['value'] is None or test['offset'] is None:
        return False, None

    last_end = content_matches[-1]['end'] if content_matches else 0
    offset = test['offset'] + (last_end if test['relative'] else 0)
    if offset < 0 or offset + test['size'] > len(payload_bytes):
        return False, None

    raw_value = payload_bytes[offset:offset + test['size']]
    try:
        value = int.from_bytes(raw_value, byteorder=test.get('endian', 'big'), signed=test.get('signed', False))
    except OverflowError:
        return False, None

    op = test['operator']
    target = test['value']
    result = False
    if op in ('>', 'gt'):
        result = value > target
    elif op in ('<', 'lt'):
        result = value < target
    elif op in ('==', '=', 'eq'):
        result = value == target
    elif op in ('!=', 'ne'):
        result = value != target
    elif op in ('>=', 'ge'):
        result = value >= target
    elif op in ('<=', 'le'):
        result = value <= target
    return result, (offset, offset + test['size'])


def match_rule_byte_tests(payload, tests, content_matches):
    results = []
    for test in tests:
        ok, span = evaluate_byte_test(payload, test, content_matches)
        results.append({'test': test, 'ok': ok, 'span': span})
        if not ok:
            return False, results
    return True, results


def evaluate_isdataat(payload, tests, content_matches):
    results = []
    for test in tests:
        required = test['count'] if test['count'] is not None else 0
        base = content_matches[-1]['end'] if test['relative'] and content_matches else 0
        available = len(payload) - base
        ok = available >= required
        results.append({'test': test, 'ok': ok, 'available': available})
        if not ok:
            return False, results
    return True, results


def rule_matches_threshold(rule_text, content_match_count):
    threshold = parse_rule_threshold(rule_text)
    if not threshold:
        return True, None

    count = int(threshold.get('count', 1)) if threshold.get('count') and threshold.get('count').isdigit() else 1
    if content_match_count < count:
        return False, threshold
    return True, threshold


def render_content_box(content_infos, metadata=None, colorize=False):
    content_box.config(state=tk.NORMAL)
    content_box.delete("1.0", tk.END)
    contents = []

    if metadata:
        content_box.insert(tk.END, "Rule metadata:\n", "metaheader")
        for key in ['classtype', 'flow', 'flowbits', 'fast_pattern', 'tag', 'priority', 'metadata', 'reference']:
            value = metadata.get(key)
            if value:
                content_box.insert(tk.END, f"{key}: {value}\n", "metakey")
        if metadata.get('other'):
            content_box.insert(tk.END, "other: " + str(metadata['other']) + "\n", "metakey")
        content_box.insert(tk.END, "\n")

    for item in content_infos:
        result_str = format_content_item(item)
        contents.append(result_str)

        if colorize:
            converted_text = convert_hex_to_ascii(result_str)
            index = 0
            parts = converted_text.split(',')
            for part in parts:
                tag = ['black', 'blue', 'red', 'green', 'orange', 'violet'][min(index, 5)]
                content_box.insert(tk.END, part + ("," if index < len(parts) - 1 else ""), tag)
                index += 1
            content_box.insert(tk.END, "\n")
        else:
            content_box.insert(tk.END, result_str + "\n")

    content_box.tag_config("black", foreground="black")
    content_box.tag_config("blue", foreground="blue")
    content_box.tag_config("red", foreground="red")
    content_box.tag_config("green", foreground="green")
    content_box.tag_config("orange", foreground="orange")
    content_box.tag_config("violet", foreground="violet")
    content_box.config(state=tk.DISABLED)
    return "\n".join(contents)


def get_content_in_ascii():
    input_text.tag_remove("highlight", "1.0", tk.END)
    selected_rule = rule_text.get("1.0", tk.END).strip()
    content_infos = parse_rule_contents(selected_rule)
    if not content_infos:
        render_content_box([])
        return
    render_content_box(content_infos, colorize=True)
    check_content()


# selekce a zobrazeni zvoleneho pravidla
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

        pcre_text = "\n".join(pcre_values)

        pcre_box.config(state=tk.NORMAL)
        pcre_box.delete("1.0", tk.END)
        pcre_box.insert(tk.END, pcre_text)
        pcre_box.tag_add("center", "1.0", "end")
        pcre_box.config(state=tk.DISABLED)

        content_infos = parse_rule_contents(selected_rule)
        metadata = parse_rule_metadata(selected_rule)
        if content_infos:
            render_content_box(content_infos, metadata=metadata)
        else:
            content_box.config(state=tk.NORMAL)
            content_box.delete("1.0", tk.END)
            if any(metadata.values()):
                render_content_box([], metadata=metadata)
            else:
                content_box.insert(tk.END, "No content sections found in this rule.")
            content_box.config(state=tk.DISABLED)

        check_content()

def filter_rules(search_text):
    matching_msgs = []
    matching_rules = []
    search_text_lower = search_text.lower().strip()
    if not search_text_lower:
        return msg_values.copy(), rules.copy()

    for rule, lower_rule in zip(rules, rules_lower):
        if search_text_lower in lower_rule:
            matching_rules.append(rule)
            match = msg_pattern.search(rule)
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
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            rules.clear()
            rules_lower.clear()
            msg_values.clear()
            for line in file:
                if 'sid' not in line:
                    continue
                if not sid_pattern.search(line):
                    continue
                cleaned_line = line.lstrip('#').strip()
                if not cleaned_line:
                    continue
                rules.append(cleaned_line)
                rules_lower.append(cleaned_line.lower())
                match = msg_pattern.search(cleaned_line)
                if match:
                    msg_values.append(match.group(1))
            filtered_rules = rules.copy()
            rule_combobox['values'] = msg_values

def open_documentation():
    docs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'suricata-latest'))
    if not os.path.isdir(docs_dir):
        messagebox.showerror('Documentation not found', f'Documentation folder not found:\n{docs_dir}')
        return

    html_files = [f for f in os.listdir(docs_dir) if f.lower().endswith('.html')]
    if not html_files:
        messagebox.showerror('Documentation not found', f'No HTML documentation file found in:\n{docs_dir}')
        return

    documentation_path = os.path.join(docs_dir, html_files[0])
    webbrowser.open('file://' + documentation_path)

def check_content(event=None):
    input_text.tag_remove("match_content", "1.0", tk.END)
    input_text.tag_remove("match_pcre", "1.0", tk.END)
    input_text.tag_remove("match_byte_test", "1.0", tk.END)

    input_text_content = decode_payload_text(input_text.get("1.0", tk.END).strip())
    selected_rule = rule_text.get("1.0", tk.END)

    content_infos = parse_rule_contents(selected_rule)
    pcre_values = suricata_parser.extract_pcre(selected_rule)
    byte_tests = parse_rule_byte_tests(selected_rule)

    rule_ok, content_matches = match_rule_contents(input_text_content, content_infos)
    pcre_matches, invalid_pcre = match_rule_pcre(input_text_content, pcre_values)
    byte_ok, byte_results = match_rule_byte_tests(input_text_content, byte_tests, content_matches)

    if rule_ok and content_matches:
        for match in content_matches:
            input_text.tag_add("match_content", f"1.0+{match['start']}c", f"1.0+{match['end']}c")

    if pcre_matches:
        for match in pcre_matches:
            input_text.tag_add("match_pcre", f"1.0+{match['start']}c", f"1.0+{match['end']}c")

    for result in byte_results:
        if result['ok'] and result['span'] is not None:
            start, end = result['span']
            input_text.tag_add("match_byte_test", f"1.0+{start}c", f"1.0+{end}c")

    input_text.tag_config("match_content", background="yellow")
    input_text.tag_config("match_pcre", foreground="green", underline=1)
    input_text.tag_config("match_byte_test", background="#ffcccb")

    return bool(content_matches), bool(pcre_matches)
def export_rules():
    search_text = search_entry.get().lower().strip()
    if not search_text:
        matching_rules = rules.copy()
    else:
        matching_rules = [rule for rule, lower_rule in zip(rules, rules_lower) if search_text in lower_rule]

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
def show_info():
    info_window = tk.Toplevel(root)
    info_window.title("Info")
   

    # Set a fixed size for the new window
    info_window.geometry("400x350")

    # Create a Text widget
    text_widget = tk.Text(info_window, wrap="word", width=50, height=8)
    text_widget.pack(pady=10, padx=10)

    # Define the text to be displayed
    text = "Suricater is a tool for signature analysis. \n Using Signatures and Choose - Load file with signatures. \n Using Signatures and Export - Download signatures based on a filter in the search bar. \n Use the Rule Tester tab to write custom rules and validate them against a payload."

    # Create a base font and an italic font
    base_font = font.Font(family="Helvetica", size=11)
    italic_font = font.Font(family="Helvetica", size=11, weight="bold", slant="italic")

    # Apply the base font to the entire Text widget
    text_widget.configure(font=base_font)

    # Insert the text into the Text widget
    text_widget.insert("1.0", text)

    # Apply the italic font to the specific words
    def apply_italic(word):
        start_index = "1.0"
        while True:
            start_index = text_widget.search(word, start_index, stopindex="end")
            if not start_index:
                break
            end_index = f"{start_index}+{len(word)}c"
            text_widget.tag_add(word, start_index, end_index)
            start_index = end_index

    apply_italic("Signatures")
    apply_italic("Choose")
    apply_italic("Export")

    # Configure the italic tag for both words
    text_widget.tag_configure("Signatures", font=italic_font)
    text_widget.tag_configure("Choose", font=italic_font)
    text_widget.tag_configure("Export", font=italic_font)

    # Make the Text widget read-only
    text_widget.config(state=tk.DISABLED)

    text_widget.tag_configure("center", justify='center')
    text_widget.tag_add("center", "1.0", "end")
    # Add a button to close the window
    close_button = tk.Button(info_window, text="Close", command=info_window.destroy)
    close_button.pack(pady=10)

def open_rule_tester_tab():
    signatures_frame.grid_remove()
    tester_frame.grid()


def open_signatures_tab():
    tester_frame.grid_remove()
    signatures_frame.grid()


def copy_rule_to_tester():
    selected_rule_text = rule_text.get("1.0", tk.END).strip()
    if not selected_rule_text:
        messagebox.showinfo("Copy rule", "No selected rule is available to copy.")
        return
    rule_builder_text.config(state=tk.NORMAL)
    rule_builder_text.delete("1.0", tk.END)
    rule_builder_text.insert(tk.END, selected_rule_text)
    rule_builder_text.config(state=tk.NORMAL)
    open_rule_tester_tab()


def test_rule():
    rule_text_value = rule_builder_text.get("1.0", tk.END).strip()
    payload_value = tester_payload_text.get("1.0", tk.END).strip()
    tester_result_box.config(state=tk.NORMAL)
    tester_result_box.delete("1.0", tk.END)
    tester_payload_text.tag_remove("match_content", "1.0", tk.END)
    tester_payload_text.tag_remove("match_pcre", "1.0", tk.END)
    tester_payload_text.tag_remove("match_byte_test", "1.0", tk.END)

    if not rule_text_value:
        messagebox.showinfo("Rule Tester", "Enter a Suricata rule to test.")
        tester_result_box.config(state=tk.DISABLED)
        return

    if not payload_value:
        messagebox.showinfo("Rule Tester", "Enter payload text to test against.")
        tester_result_box.config(state=tk.DISABLED)
        return

    payload_value = decode_payload_text(payload_value)
    content_infos = parse_rule_contents(rule_text_value)
    metadata = parse_rule_metadata(rule_text_value)
    pcre_values = suricata_parser.extract_pcre(rule_text_value)
    byte_tests = parse_rule_byte_tests(rule_text_value)
    isdataat_tests = parse_rule_isdataat(rule_text_value)

    rule_ok, content_matches = match_rule_contents(payload_value, content_infos)
    pcre_matches, invalid_patterns = match_rule_pcre(payload_value, pcre_values)
    byte_ok, byte_results = match_rule_byte_tests(payload_value, byte_tests, content_matches)
    isdataat_ok, isdataat_results = evaluate_isdataat(payload_value, isdataat_tests, content_matches)

    for match in content_matches:
        tester_payload_text.tag_add("match_content", f"1.0+{match['start']}c", f"1.0+{match['end']}c")
    for match in pcre_matches:
        tester_payload_text.tag_add("match_pcre", f"1.0+{match['start']}c", f"1.0+{match['end']}c")
    for result in byte_results:
        if result['ok'] and result['span'] is not None:
            start, end = result['span']
            tester_payload_text.tag_add("match_byte_test", f"1.0+{start}c", f"1.0+{end}c")

    tester_payload_text.tag_config("match_content", background="#fff49c")
    tester_payload_text.tag_config("match_pcre", background="#c6f7c6")
    tester_payload_text.tag_config("match_byte_test", background="#ffcccb")

    threshold_ok, threshold_info = rule_matches_threshold(rule_text_value, len(content_matches))
    fired = rule_ok and bool(pcre_matches) if pcre_values else rule_ok
    if not threshold_ok:
        fired = False

    result_lines = [
        f"Rule tested: {len([item for item in content_infos if not item.get('negated')])} positive content section(s), "
        f"{len([item for item in content_infos if item.get('negated')])} negative content section(s), {len(pcre_values)} PCRE pattern(s), "
        f"{len(byte_tests)} byte_test(s), {len(isdataat_tests)} isdataat(s)"
    ]
    if metadata and any(metadata.values()):
        metadata_summary = [f"{k}={v}" for k, v in metadata.items() if v and k != 'other']
        if metadata.get('other'):
            metadata_summary.append(f"other={metadata['other']}")
        result_lines.append("Parsed metadata: " + ", ".join(metadata_summary))
    result_lines.append(f"Content sequence match: {'yes' if rule_ok else 'no'}")
    result_lines.append(f"PCRE sequence match: {'yes' if bool(pcre_matches) else 'no'}")
    result_lines.append(f"byte_test match: {'yes' if byte_ok else 'no'}")
    result_lines.append(f"isdataat match: {'yes' if isdataat_ok else 'no'}")

    if threshold_info:
        result_lines.append(f"Threshold configured: {threshold_info}")
        result_lines.append(
            f"Threshold satisfied: {'yes' if threshold_ok else 'no'} (count {threshold_info.get('count', '1')})"
        )

    result_lines.append(f"Rule fired: {'yes' if fired else 'no'}")

    if invalid_patterns:
        result_lines.append("Invalid PCRE patterns:")
        for pattern in invalid_patterns:
            result_lines.append(f"  - {pattern}")

    tester_result_box.insert(tk.END, "\n".join(result_lines))
    if fired:
        tester_result_box.tag_configure("fired", foreground="#1f7a1f")
        start_index = tester_result_box.search("Rule fired:", "1.0", stopindex="end")
        if start_index:
            end_index = f"{start_index}+{len(result_lines[-1])}c"
            tester_result_box.tag_add("fired", start_index, end_index)
    else:
        tester_result_box.tag_configure("notfired", foreground="#a00")
        start_index = tester_result_box.search("Rule fired:", "1.0", stopindex="end")
        if start_index:
            end_index = f"{start_index}+{len(result_lines[-1])}c"
            tester_result_box.tag_add("notfired", start_index, end_index)

    tester_result_box.config(state=tk.DISABLED)


def generate_rule():
    action = action_entry.get().strip() or 'alert'
    proto = proto_entry.get().strip() or 'tcp'
    src_ip = src_ip_entry.get().strip() or 'any'
    src_port = src_port_entry.get().strip() or 'any'
    direction = direction_combo.get().strip() or '->'
    dst_ip = dst_ip_entry.get().strip() or 'any'
    dst_port = dst_port_entry.get().strip() or 'any'
    msg = msg_entry.get().strip() or 'generated rule'
    sid = sid_entry.get().strip() or '1000001'
    content_value = content_entry.get().strip()
    pcre_value = pcre_entry.get().strip()

    options = [f'msg:"{msg}"', f'sid:{sid}']
    if content_value:
        options.append(f'content:"{content_value}"')
    if pcre_value:
        options.append(f'pcre:"{pcre_value}"')

    rule_text_value = f"{action} {proto} {src_ip} {src_port} {direction} {dst_ip} {dst_port} ({'; '.join(options)};)"
    rule_builder_text.config(state=tk.NORMAL)
    rule_builder_text.delete("1.0", tk.END)
    rule_builder_text.insert(tk.END, rule_text_value)
    rule_builder_text.config(state=tk.NORMAL)
    open_rule_tester_tab()


def save_generated_rule():
    rule_text_value = rule_builder_text.get("1.0", tk.END).strip()
    if not rule_text_value:
        messagebox.showinfo("Save Rule", "No rule text available to save.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".rules", filetypes=[("Suricata Rules", "*.rules")])
    if not file_path:
        return

    try:
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(rule_text_value.strip() + '\n')
        messagebox.showinfo("Save Rule", f"Rule saved to {file_path}")
    except Exception as e:
        messagebox.showerror("Save Rule", f"Could not save rule: {e}")


def convert_ascii_button_action():
    select_rule(None)
    check_content()

def perform_search(event=None):
    update_combobox_options(search_entry.get())


root = tk.Tk()
root.title("SURICATER")
root.option_add("*TCombobox*Listbox.font", "Helevetica 10")

# vychozi nastaveni okna
root.minsize(1100, 900)
root.geometry(f"1300x900")
menu_font = ("Helvetica", 10)

# menu
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

# top-level menus
signatures_menu = tk.Menu(menu_bar, tearoff=0, font=menu_font)
tester_menu = tk.Menu(menu_bar, tearoff=0, font=menu_font)
help_menu = tk.Menu(menu_bar, tearoff=0, font=menu_font)

menu_bar.add_cascade(label="Signatures", menu=signatures_menu)
menu_bar.add_cascade(label="Rule Tester", menu=tester_menu)
menu_bar.add_cascade(label="Help", menu=help_menu)

signatures_menu.add_command(label="Choose", command=choose_file_action)
signatures_menu.add_command(label="Export", command=export_rules)
signatures_menu.add_separator()
signatures_menu.add_command(label="Show Signatures", command=open_signatures_tab)

tester_menu.add_command(label="Open Tester", command=open_rule_tester_tab)
tester_menu.add_command(label="Copy selected rule", command=copy_rule_to_tester)

tester_menu.add_separator()
tester_menu.add_command(label="Generate Rule", command=generate_rule)
tester_menu.add_command(label="Save Rule", command=save_generated_rule)

help_menu.add_command(label="Documentation", command=open_documentation)
help_menu.add_command(label="Info", command=show_info)

signatures_frame = ttk.Frame(root)
tester_frame = ttk.Frame(root)

signatures_frame.grid(row=0, column=0, sticky="nsew")
tester_frame.grid(row=0, column=0, sticky="nsew")

tester_frame.grid_remove()

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

rules = []
rules_lower = []
msg_values = []
suricata_parser = SuricataRuleParser()
filtered_rules = rules.copy()

rule_builder_text = None
tester_payload_text = None
tester_result_box = None

# search
search_label = tk.Label(signatures_frame, text="Search:", font=("Helvetica", 10))
search_label.grid(row=0, column=0, padx=10, sticky="w")

# combobox
rules_label = tk.Label(signatures_frame, text="Rules:", font=("Helvetica", 10))
rules_label.grid(row=0, column=1, padx=10, sticky="w")

rule_combobox = ttk.Combobox(signatures_frame, values=msg_values, width=100, font=("Helvetica", 11))
rule_combobox.grid(row=1, column=1, columnspan=8, padx=10, pady=(0, 10), sticky="w")

rule_combobox['state'] = 'readonly'

# searchbox
search_entry = tk.Entry(signatures_frame, width=40, font=("Helvetica", 11))
search_entry.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="w")

# search_button
search_button = ttk.Button(signatures_frame, text="Search", command=perform_search, width=10)
search_button.grid(row=1, column=0, padx=5, pady=(0, 10), sticky="e")

search_entry.bind('<Return>', perform_search)

# selected rule
rule_label = tk.Label(signatures_frame, text="Selected rule:", font=("Helvetica", 10))
rule_label.grid(row=2, column=0, columnspan=9, padx=10, sticky="sw")

rule_text = tk.Text(signatures_frame, wrap=tk.WORD, width=400, height=7, font=("Helvetica", 12))
rule_text.grid(row=3, column=0, columnspan=9, padx=10, pady=(0, 5))
rule_text.tag_configure("center", justify='center')
rule_text.config(state=tk.DISABLED)

# scrollball
rule_text_scrollbar = ttk.Scrollbar(signatures_frame, orient=tk.VERTICAL, command=rule_text.yview)
rule_text_scrollbar.grid(row=3, column=9, sticky='ns')
rule_text.config(yscrollcommand=rule_text_scrollbar.set)

# button from hex
convert_content_button = ttk.Button(signatures_frame, text="To ASCII", command=get_content_in_ascii, width=17)
convert_content_button.grid(row=6, column=0, pady=5, sticky="e")

# refresh button
convert_ascii_button = ttk.Button(signatures_frame, text="Refresh", command=convert_ascii_button_action, width=17)
convert_ascii_button.grid(row=6, column=1, padx=5, sticky="e")

# copy to tester button
copy_to_tester_button = ttk.Button(signatures_frame, text="Load to Tester", command=copy_rule_to_tester, width=17)
copy_to_tester_button.grid(row=6, column=2, padx=5, sticky="e")

# content
content_label = tk.Label(signatures_frame, text="Content:", font=("Helvetica", 10))
content_label.grid(row=4, column=0, columnspan=9, padx=10, pady=(0, 5), sticky="sw")

content_box = tk.Text(signatures_frame, wrap=tk.WORD, width=400, height=7, font=("Helvetica", 11))
content_box.grid(row=5, column=0, columnspan=9, padx=10, pady=(0, 5), sticky="w")
content_box.config(state=tk.DISABLED)
content_box.tag_configure("metaheader", font=("Helvetica", 11, "bold"))
content_box.tag_configure("metakey", foreground="#2c3e50")

content_box_scrollbar = ttk.Scrollbar(signatures_frame, orient=tk.VERTICAL, command=content_box.yview)
content_box_scrollbar.grid(row=5, column=9, sticky='ns')
content_box.config(yscrollcommand=content_box_scrollbar.set)

# pcre
pcre_label = tk.Label(signatures_frame, text="Pcre:", font=("Helvetica", 10))
pcre_label.grid(row=6, column=0, columnspan=9, padx=10, pady=(10, 5), sticky="sw")

pcre_box = tk.Text(signatures_frame, wrap=tk.WORD, width=400, height=2, font=("Helvetica", 11))
pcre_box.grid(row=7, column=0, columnspan=9, padx=10, pady=(0, 10), sticky="w")
pcre_box.config(state=tk.DISABLED)

pcre_box_scrollbar = ttk.Scrollbar(signatures_frame, orient=tk.VERTICAL, command=pcre_box.yview)
pcre_box_scrollbar.grid(row=7, column=9, sticky='ns')
pcre_box.config(yscrollcommand=pcre_box_scrollbar.set)

# input payload
input_label = tk.Label(signatures_frame, text="Input payload:", font=("Helvetica", 10))
input_label.grid(row=8, column=0, columnspan=8, padx=10, sticky="sw")

input_text = tk.Text(signatures_frame, wrap=tk.WORD, width=400, height=8, font=("Helvetica", 11))
input_text.grid(row=9, column=0, columnspan=9, padx=10)

input_text_scrollbar = ttk.Scrollbar(signatures_frame, orient=tk.VERTICAL, command=input_text.yview)
input_text_scrollbar.grid(row=9, column=9, sticky='ns')
input_text.config(yscrollcommand=input_text_scrollbar.set)

input_text.bind('<KeyRelease>', check_content)

# Rule tester UI
rule_generator_label = tk.Label(tester_frame, text="Rule Generator", font=("Helvetica", 12, "bold"))
rule_generator_label.grid(row=0, column=0, columnspan=4, padx=10, pady=(10, 5), sticky="w")

action_label = tk.Label(tester_frame, text="Action:", font=("Helvetica", 10))
action_label.grid(row=1, column=0, padx=10, pady=2, sticky="w")
action_entry = tk.Entry(tester_frame, width=12, font=("Helvetica", 11))
action_entry.grid(row=1, column=1, padx=5, pady=2, sticky="w")
action_entry.insert(0, "alert")

proto_label = tk.Label(tester_frame, text="Proto:", font=("Helvetica", 10))
proto_label.grid(row=1, column=2, padx=10, pady=2, sticky="w")
proto_entry = tk.Entry(tester_frame, width=12, font=("Helvetica", 11))
proto_entry.grid(row=1, column=3, padx=5, pady=2, sticky="w")
proto_entry.insert(0, "tcp")

src_ip_label = tk.Label(tester_frame, text="Src IP:", font=("Helvetica", 10))
src_ip_label.grid(row=2, column=0, padx=10, pady=2, sticky="w")
src_ip_entry = tk.Entry(tester_frame, width=14, font=("Helvetica", 11))
src_ip_entry.grid(row=2, column=1, padx=5, pady=2, sticky="w")
src_ip_entry.insert(0, "any")

src_port_label = tk.Label(tester_frame, text="Src Port:", font=("Helvetica", 10))
src_port_label.grid(row=2, column=2, padx=10, pady=2, sticky="w")
src_port_entry = tk.Entry(tester_frame, width=14, font=("Helvetica", 11))
src_port_entry.grid(row=2, column=3, padx=5, pady=2, sticky="w")
src_port_entry.insert(0, "any")

arrow_label = tk.Label(tester_frame, text="Direction:", font=("Helvetica", 10))
arrow_label.grid(row=3, column=0, padx=10, pady=2, sticky="w")
direction_combo = ttk.Combobox(tester_frame, values=["->", "<>"], width=6, font=("Helvetica", 11), state='readonly')
direction_combo.grid(row=3, column=1, padx=5, pady=2, sticky="w")
direction_combo.set("->")

dst_ip_label = tk.Label(tester_frame, text="Dst IP:", font=("Helvetica", 10))
dst_ip_label.grid(row=3, column=2, padx=10, pady=2, sticky="w")
dst_ip_entry = tk.Entry(tester_frame, width=14, font=("Helvetica", 11))
dst_ip_entry.grid(row=3, column=3, padx=5, pady=2, sticky="w")
dst_ip_entry.insert(0, "any")

dst_port_label = tk.Label(tester_frame, text="Dst Port:", font=("Helvetica", 10))
dst_port_label.grid(row=4, column=0, padx=10, pady=2, sticky="w")
dst_port_entry = tk.Entry(tester_frame, width=14, font=("Helvetica", 11))
dst_port_entry.grid(row=4, column=1, padx=5, pady=2, sticky="w")
dst_port_entry.insert(0, "any")

msg_label = tk.Label(tester_frame, text="msg:", font=("Helvetica", 10))
msg_label.grid(row=4, column=2, padx=10, pady=2, sticky="w")
msg_entry = tk.Entry(tester_frame, width=40, font=("Helvetica", 11))
msg_entry.grid(row=4, column=3, padx=5, pady=2, sticky="w")
msg_entry.insert(0, "generated rule")

sid_label = tk.Label(tester_frame, text="sid:", font=("Helvetica", 10))
sid_label.grid(row=5, column=0, padx=10, pady=2, sticky="w")
sid_entry = tk.Entry(tester_frame, width=14, font=("Helvetica", 11))
sid_entry.grid(row=5, column=1, padx=5, pady=2, sticky="w")
sid_entry.insert(0, "1000001")

content_label_tester = tk.Label(tester_frame, text="Content:", font=("Helvetica", 10))
content_label_tester.grid(row=5, column=2, padx=10, pady=2, sticky="w")
content_entry = tk.Entry(tester_frame, width=40, font=("Helvetica", 11))
content_entry.grid(row=5, column=3, padx=5, pady=2, sticky="w")

pcre_label_tester = tk.Label(tester_frame, text="PCRE:", font=("Helvetica", 10))
pcre_label_tester.grid(row=6, column=0, padx=10, pady=2, sticky="w")
pcre_entry = tk.Entry(tester_frame, width=80, font=("Helvetica", 11))
pcre_entry.grid(row=6, column=1, columnspan=3, padx=5, pady=2, sticky="w")

generate_button = ttk.Button(tester_frame, text="Generate Rule", command=generate_rule, width=15)
generate_button.grid(row=7, column=0, padx=10, pady=(5, 10), sticky="w")

save_rule_button = ttk.Button(tester_frame, text="Save Rule", command=save_generated_rule, width=15)
save_rule_button.grid(row=7, column=1, padx=10, pady=(5, 10), sticky="w")

rule_builder_label = tk.Label(tester_frame, text="Rule text:", font=("Helvetica", 10))
rule_builder_label.grid(row=8, column=0, columnspan=4, padx=10, pady=(10, 5), sticky="sw")

rule_builder_text = tk.Text(tester_frame, wrap=tk.WORD, width=120, height=8, font=("Helvetica", 11))
rule_builder_text.grid(row=9, column=0, columnspan=4, padx=10, pady=(0, 10), sticky="nsew")

rule_builder_scrollbar = ttk.Scrollbar(tester_frame, orient=tk.VERTICAL, command=rule_builder_text.yview)
rule_builder_scrollbar.grid(row=9, column=4, sticky='ns', pady=(0, 10))
rule_builder_text.config(yscrollcommand=rule_builder_scrollbar.set)

payload_label = tk.Label(tester_frame, text="Test payload:", font=("Helvetica", 10))
payload_label.grid(row=10, column=0, columnspan=4, padx=10, sticky="sw")

tester_payload_text = tk.Text(tester_frame, wrap=tk.WORD, width=120, height=6, font=("Helvetica", 11))
tester_payload_text.grid(row=11, column=0, columnspan=4, padx=10, pady=(0, 10), sticky="nsew")

tester_payload_scrollbar = ttk.Scrollbar(tester_frame, orient=tk.VERTICAL, command=tester_payload_text.yview)
tester_payload_scrollbar.grid(row=11, column=4, sticky='ns', pady=(0, 10))
tester_payload_text.config(yscrollcommand=tester_payload_scrollbar.set)

run_test_button = ttk.Button(tester_frame, text="Test Rule", command=test_rule, width=15)
run_test_button.grid(row=12, column=0, padx=10, pady=(0, 10), sticky="w")

tester_result_label = tk.Label(tester_frame, text="Test result:", font=("Helvetica", 10))
tester_result_label.grid(row=13, column=0, columnspan=4, padx=10, sticky="sw")

tester_result_box = tk.Text(tester_frame, wrap=tk.WORD, width=120, height=8, font=("Helvetica", 11), state=tk.DISABLED)
tester_result_box.grid(row=14, column=0, columnspan=4, padx=10, pady=(0, 10), sticky="nsew")

tester_result_scrollbar = ttk.Scrollbar(tester_frame, orient=tk.VERTICAL, command=tester_result_box.yview)
tester_result_scrollbar.grid(row=14, column=4, sticky='ns', pady=(0, 10))
tester_result_box.config(yscrollcommand=tester_result_scrollbar.set)

# konfigurace oken a rozlozeni
signatures_frame.grid_rowconfigure(3, weight=1)
signatures_frame.grid_rowconfigure(5, weight=1)
signatures_frame.grid_rowconfigure(9, weight=1)
signatures_frame.grid_columnconfigure(0, weight=1)
signatures_frame.grid_columnconfigure(1, weight=1)
signatures_frame.grid_columnconfigure(2, weight=1)
signatures_frame.grid_columnconfigure(3, weight=1)
signatures_frame.grid_columnconfigure(4, weight=1)
signatures_frame.grid_columnconfigure(5, weight=1)
signatures_frame.grid_columnconfigure(6, weight=1)
signatures_frame.grid_columnconfigure(7, weight=1)
signatures_frame.grid_columnconfigure(8, weight=1)

tester_frame.grid_rowconfigure(9, weight=1)
tester_frame.grid_rowconfigure(11, weight=1)
tester_frame.grid_rowconfigure(14, weight=1)
tester_frame.grid_columnconfigure(0, weight=1)
tester_frame.grid_columnconfigure(1, weight=1)
tester_frame.grid_columnconfigure(2, weight=1)
tester_frame.grid_columnconfigure(3, weight=1)

rule_combobox.bind('<<ComboboxSelected>>', select_rule)
input_text.bind('<KeyRelease>', check_content)

# start
root.mainloop()