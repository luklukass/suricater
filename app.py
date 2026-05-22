import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font
import re
import webbrowser

from rule_parser import (
    SuricataRuleParser, sid_pattern, msg_pattern,
    parse_rule_contents, parse_rule_metadata, parse_rule_byte_tests,
    parse_rule_isdataat, parse_rule_threshold, format_content_item,
    convert_hex_to_ascii, decode_suricata_string, decode_payload_text,
)
from rule_matcher import (
    match_rule_contents, match_rule_pcre, match_rule_byte_tests,
    evaluate_isdataat, rule_matches_threshold,
)


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("SURICATER")
        self.root.option_add("*TCombobox*Listbox.font", "Helvetica 10")
        self.root.minsize(1100, 900)
        self.root.geometry("1300x900")

        # --- Data state ---
        self.rules = []
        self.rules_lower = []
        self.msg_values = []
        self.filtered_rules = []
        self.filtered_msgs = []
        self.current_rule_page = 0
        self.rules_per_page = 1000
        self.selected_rule_content_infos = []
        self.content_item_tag_map = {}
        self.suricata_parser = SuricataRuleParser()

        self._build_ui()

    # ------------------------------------------------------------------ #
    #  UI construction                                                     #
    # ------------------------------------------------------------------ #

    def _build_ui(self):
        self._build_menu()
        self._build_frames()
        self._build_signatures_tab()
        self._build_tester_tab()
        self._configure_layout()
        self._bind_events()

    def _build_menu(self):
        menu_font = ("Helvetica", 10)
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        sig_menu = tk.Menu(menu_bar, tearoff=0, font=menu_font)
        tester_menu = tk.Menu(menu_bar, tearoff=0, font=menu_font)
        help_menu = tk.Menu(menu_bar, tearoff=0, font=menu_font)

        menu_bar.add_cascade(label="Signatures", menu=sig_menu)
        menu_bar.add_cascade(label="Rule Tester", menu=tester_menu)
        menu_bar.add_cascade(label="Help", menu=help_menu)

        sig_menu.add_command(label="Choose", command=self.choose_file_action)
        sig_menu.add_command(label="Export", command=self.export_rules)
        sig_menu.add_separator()
        sig_menu.add_command(label="Show Signatures", command=self.open_signatures_tab)

        tester_menu.add_command(label="Open Tester", command=self.open_rule_tester_tab)
        tester_menu.add_command(label="Copy selected rule", command=self.copy_rule_to_tester)
        tester_menu.add_separator()
        tester_menu.add_command(label="Generate Rule", command=self.generate_rule)
        tester_menu.add_command(label="Save Rule", command=self.save_generated_rule)

        help_menu.add_command(label="Documentation", command=self.open_documentation)
        help_menu.add_command(label="Info", command=self.show_info)

    def _build_frames(self):
        self.signatures_frame = ttk.Frame(self.root)
        self.tester_frame = ttk.Frame(self.root)
        self.signatures_frame.grid(row=0, column=0, sticky="nsew")
        self.tester_frame.grid(row=0, column=0, sticky="nsew")
        self.tester_frame.grid_remove()
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def _build_signatures_tab(self):
        f = self.signatures_frame

        tk.Label(f, text="Search:", font=("Helvetica", 10)).grid(row=0, column=0, padx=10, sticky="w")
        tk.Label(f, text="Rules:", font=("Helvetica", 10)).grid(row=0, column=1, padx=10, sticky="w")

        self.rule_combobox = ttk.Combobox(f, values=[], width=100, font=("Helvetica", 11), state='readonly')
        self.rule_combobox.grid(row=1, column=1, columnspan=8, padx=10, pady=(0, 10), sticky="w")

        self.search_entry = tk.Entry(f, width=40, font=("Helvetica", 11))
        self.search_entry.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="w")

        ttk.Button(f, text="Search", command=self.perform_search, width=10).grid(
            row=1, column=0, padx=5, pady=(0, 10), sticky="e")

        self.loading_label = tk.Label(f, text="", font=("Helvetica", 10), fg="blue")
        self.loading_label.grid(row=0, column=9, sticky="e", padx=10)

        self.page_label = tk.Label(f, text="Page 1/1", font=("Helvetica", 10))
        self.page_label.grid(row=0, column=5, padx=10, sticky="w")

        self.page_size_combo = ttk.Combobox(f, values=[100, 500, 1000, 2000], width=6,
                                             font=("Helvetica", 11), state='readonly')
        self.page_size_combo.set(self.rules_per_page)
        self.page_size_combo.grid(row=0, column=6, padx=5, sticky="w")
        self.page_size_combo.bind('<<ComboboxSelected>>', self.set_rules_per_page)

        ttk.Button(f, text="Prev", command=lambda: self.change_rule_page(-1), width=7).grid(
            row=0, column=7, padx=2, sticky="w")
        ttk.Button(f, text="Next", command=lambda: self.change_rule_page(1), width=7).grid(
            row=0, column=8, padx=2, sticky="w")

        tk.Label(f, text="Selected rule:", font=("Helvetica", 10)).grid(
            row=2, column=0, columnspan=9, padx=10, sticky="sw")

        self.rule_text = tk.Text(f, wrap=tk.WORD, width=400, height=7, font=("Helvetica", 12))
        self.rule_text.grid(row=3, column=0, columnspan=9, padx=10, pady=(0, 5))
        self.rule_text.tag_configure("center", justify='center')
        self.rule_text.config(state=tk.DISABLED)

        rule_sb = ttk.Scrollbar(f, orient=tk.VERTICAL, command=self.rule_text.yview)
        rule_sb.grid(row=3, column=9, sticky='ns')
        self.rule_text.config(yscrollcommand=rule_sb.set)

        tk.Label(f, text="Content:", font=("Helvetica", 10)).grid(
            row=4, column=0, columnspan=9, padx=10, pady=(0, 5), sticky="sw")

        self.content_box = tk.Text(f, wrap=tk.WORD, width=400, height=7, font=("Helvetica", 11))
        self.content_box.grid(row=5, column=0, columnspan=9, padx=10, pady=(0, 5), sticky="w")
        self.content_box.config(state=tk.DISABLED)
        self.content_box.tag_configure("metaheader", font=("Helvetica", 11, "bold"))
        self.content_box.tag_configure("metakey", foreground="#2c3e50")

        content_sb = ttk.Scrollbar(f, orient=tk.VERTICAL, command=self.content_box.yview)
        content_sb.grid(row=5, column=9, sticky='ns')
        self.content_box.config(yscrollcommand=content_sb.set)

        ttk.Button(f, text="To ASCII", command=self.get_content_in_ascii, width=17).grid(
            row=6, column=0, pady=5, sticky="e")
        ttk.Button(f, text="Refresh", command=self.convert_ascii_button_action, width=17).grid(
            row=6, column=1, padx=5, sticky="e")
        ttk.Button(f, text="Load to Tester", command=self.copy_rule_to_tester, width=17).grid(
            row=6, column=2, padx=5, sticky="e")

        tk.Label(f, text="Pcre:", font=("Helvetica", 10)).grid(
            row=6, column=0, columnspan=9, padx=10, pady=(10, 5), sticky="sw")

        self.pcre_box = tk.Text(f, wrap=tk.WORD, width=400, height=2, font=("Helvetica", 11))
        self.pcre_box.grid(row=7, column=0, columnspan=9, padx=10, pady=(0, 10), sticky="w")
        self.pcre_box.config(state=tk.DISABLED)

        pcre_sb = ttk.Scrollbar(f, orient=tk.VERTICAL, command=self.pcre_box.yview)
        pcre_sb.grid(row=7, column=9, sticky='ns')
        self.pcre_box.config(yscrollcommand=pcre_sb.set)

        tk.Label(f, text="Input payload:", font=("Helvetica", 10)).grid(
            row=8, column=0, columnspan=8, padx=10, sticky="sw")

        self.input_text = tk.Text(f, wrap=tk.WORD, width=400, height=8, font=("Helvetica", 11))
        self.input_text.grid(row=9, column=0, columnspan=9, padx=10)

        input_sb = ttk.Scrollbar(f, orient=tk.VERTICAL, command=self.input_text.yview)
        input_sb.grid(row=9, column=9, sticky='ns')
        self.input_text.config(yscrollcommand=input_sb.set)

    def _build_tester_tab(self):
        f = self.tester_frame

        tk.Label(f, text="Rule Generator", font=("Helvetica", 12, "bold")).grid(
            row=0, column=0, columnspan=4, padx=10, pady=(10, 5), sticky="w")

        fields = [
            ("Action:", "action_entry", 1, 0, 1, 12, "alert"),
            ("Proto:", "proto_entry", 1, 2, 3, 12, "tcp"),
            ("Src IP:", "src_ip_entry", 2, 0, 1, 14, "any"),
            ("Src Port:", "src_port_entry", 2, 2, 3, 14, "any"),
            ("Dst IP:", "dst_ip_entry", 3, 2, 3, 14, "any"),
            ("Dst Port:", "dst_port_entry", 4, 0, 1, 14, "any"),
            ("msg:", "msg_entry", 4, 2, 3, 40, "generated rule"),
            ("sid:", "sid_entry", 5, 0, 1, 14, "1000001"),
            ("Content:", "content_entry", 5, 2, 3, 40, ""),
        ]
        for label, attr, row, lcol, ecol, width, default in fields:
            tk.Label(f, text=label, font=("Helvetica", 10)).grid(row=row, column=lcol, padx=10, pady=2, sticky="w")
            entry = tk.Entry(f, width=width, font=("Helvetica", 11))
            entry.grid(row=row, column=ecol, padx=5, pady=2, sticky="w")
            if default:
                entry.insert(0, default)
            setattr(self, attr, entry)

        tk.Label(f, text="Direction:", font=("Helvetica", 10)).grid(row=3, column=0, padx=10, pady=2, sticky="w")
        self.direction_combo = ttk.Combobox(f, values=["->", "<>"], width=6, font=("Helvetica", 11), state='readonly')
        self.direction_combo.grid(row=3, column=1, padx=5, pady=2, sticky="w")
        self.direction_combo.set("->")

        tk.Label(f, text="PCRE:", font=("Helvetica", 10)).grid(row=6, column=0, padx=10, pady=2, sticky="w")
        self.pcre_entry = tk.Entry(f, width=80, font=("Helvetica", 11))
        self.pcre_entry.grid(row=6, column=1, columnspan=3, padx=5, pady=2, sticky="w")

        ttk.Button(f, text="Generate Rule", command=self.generate_rule, width=15).grid(
            row=7, column=0, padx=10, pady=(5, 10), sticky="w")
        ttk.Button(f, text="Save Rule", command=self.save_generated_rule, width=15).grid(
            row=7, column=1, padx=10, pady=(5, 10), sticky="w")

        tk.Label(f, text="Payload Generator", font=("Helvetica", 12, "bold")).grid(
            row=8, column=0, columnspan=4, padx=10, pady=(10, 5), sticky="w")

        tk.Label(f, text="Output:", font=("Helvetica", 10)).grid(row=9, column=0, padx=10, pady=2, sticky="w")
        self.payload_output_mode = ttk.Combobox(f, values=["raw", "escaped", "hex"],
                                                 width=10, font=("Helvetica", 11), state='readonly')
        self.payload_output_mode.grid(row=9, column=1, padx=5, pady=2, sticky="w")
        self.payload_output_mode.set("raw")

        ttk.Button(f, text="DNS", command=self.generate_dns_payload, width=12).grid(
            row=9, column=2, padx=5, pady=2, sticky="w")
        ttk.Button(f, text="SIP", command=self.generate_sip_payload, width=12).grid(
            row=9, column=3, padx=5, pady=2, sticky="w")
        ttk.Button(f, text="HTTP", command=self.generate_http_payload, width=12).grid(
            row=10, column=0, padx=10, pady=2, sticky="w")
        ttk.Button(f, text="Shellcode", command=self.generate_shellcode_payload, width=12).grid(
            row=10, column=1, padx=5, pady=2, sticky="w")

        tk.Label(f, text="Rule preview / validation:", font=("Helvetica", 10)).grid(
            row=11, column=0, columnspan=4, padx=10, pady=(10, 5), sticky="sw")

        self.rule_preview_box = tk.Text(f, wrap=tk.WORD, width=120, height=6,
                                         font=("Helvetica", 11), state=tk.DISABLED)
        self.rule_preview_box.grid(row=12, column=0, columnspan=4, padx=10, pady=(0, 10), sticky="nsew")
        rp_sb = ttk.Scrollbar(f, orient=tk.VERTICAL, command=self.rule_preview_box.yview)
        rp_sb.grid(row=12, column=4, sticky='ns', pady=(0, 10))
        self.rule_preview_box.config(yscrollcommand=rp_sb.set)

        tk.Label(f, text="Rule text:", font=("Helvetica", 10)).grid(
            row=13, column=0, columnspan=4, padx=10, pady=(10, 5), sticky="sw")

        self.rule_builder_text = tk.Text(f, wrap=tk.WORD, width=120, height=8, font=("Helvetica", 11))
        self.rule_builder_text.grid(row=14, column=0, columnspan=4, padx=10, pady=(0, 10), sticky="nsew")
        rb_sb = ttk.Scrollbar(f, orient=tk.VERTICAL, command=self.rule_builder_text.yview)
        rb_sb.grid(row=14, column=4, sticky='ns', pady=(0, 10))
        self.rule_builder_text.config(yscrollcommand=rb_sb.set)
        self.rule_builder_text.tag_configure("rule_keyword", foreground="#1a237e", font=("Helvetica", 11, "bold"))
        self.rule_builder_text.tag_configure("rule_string", foreground="#b71c1c")
        self.rule_builder_text.tag_configure("rule_number", foreground="#004d40")
        self.rule_builder_text.tag_configure("rule_comment", foreground="#616161", slant="italic")
        self.rule_builder_text.bind(
            '<KeyRelease>',
            lambda e: (self.highlight_rule_syntax(self.rule_builder_text), self.validate_rule_text()),
        )

        tk.Label(f, text="Test payload:", font=("Helvetica", 10)).grid(
            row=15, column=0, columnspan=4, padx=10, sticky="sw")

        self.tester_payload_text = tk.Text(f, wrap=tk.WORD, width=120, height=6, font=("Helvetica", 11))
        self.tester_payload_text.grid(row=16, column=0, columnspan=4, padx=10, pady=(0, 10), sticky="nsew")
        tp_sb = ttk.Scrollbar(f, orient=tk.VERTICAL, command=self.tester_payload_text.yview)
        tp_sb.grid(row=16, column=4, sticky='ns', pady=(0, 10))
        self.tester_payload_text.config(yscrollcommand=tp_sb.set)

        ttk.Button(f, text="Test Rule", command=self.test_rule, width=15).grid(
            row=17, column=0, padx=10, pady=(0, 10), sticky="w")

        tk.Label(f, text="Test result:", font=("Helvetica", 10)).grid(
            row=18, column=0, columnspan=4, padx=10, sticky="sw")

        self.tester_result_box = tk.Text(f, wrap=tk.WORD, width=120, height=8,
                                          font=("Helvetica", 11), state=tk.DISABLED)
        self.tester_result_box.grid(row=19, column=0, columnspan=4, padx=10, pady=(0, 10), sticky="nsew")
        tr_sb = ttk.Scrollbar(f, orient=tk.VERTICAL, command=self.tester_result_box.yview)
        tr_sb.grid(row=19, column=4, sticky='ns', pady=(0, 10))
        self.tester_result_box.config(yscrollcommand=tr_sb.set)

    def _configure_layout(self):
        f = self.signatures_frame
        for row in (3, 5, 9):
            f.grid_rowconfigure(row, weight=1)
        for col in range(9):
            f.grid_columnconfigure(col, weight=1)

        f = self.tester_frame
        for row in (9, 11, 14):
            f.grid_rowconfigure(row, weight=1)
        for col in range(4):
            f.grid_columnconfigure(col, weight=1)

    def _bind_events(self):
        self.rule_combobox.bind('<<ComboboxSelected>>', self.select_rule)
        self.input_text.bind('<KeyRelease>', self.check_content)
        self.search_entry.bind('<Return>', self.perform_search)

    # ------------------------------------------------------------------ #
    #  Pagination                                                          #
    # ------------------------------------------------------------------ #

    def get_rule_page_count(self):
        if not self.filtered_rules:
            return 1
        return max(1, (len(self.filtered_rules) + self.rules_per_page - 1) // self.rules_per_page)

    def update_rule_page(self):
        total = self.get_rule_page_count()
        self.current_rule_page = max(0, min(self.current_rule_page, total - 1))
        start = self.current_rule_page * self.rules_per_page
        end = start + self.rules_per_page
        page_msgs = self.filtered_msgs[start:end]
        self.rule_combobox['values'] = page_msgs
        self.page_label.config(text=f"Page {self.current_rule_page + 1}/{total}")
        if page_msgs:
            self.rule_combobox.set('')

    def change_rule_page(self, delta):
        self.current_rule_page += delta
        self.update_rule_page()

    def set_rules_per_page(self, event=None):
        try:
            value = int(self.page_size_combo.get())
            if value > 0:
                self.rules_per_page = value
                self.current_rule_page = 0
                self.update_rule_page()
        except ValueError:
            pass

    # ------------------------------------------------------------------ #
    #  Syntax highlighting & validation                                    #
    # ------------------------------------------------------------------ #

    def highlight_rule_syntax(self, widget):
        text = widget.get("1.0", "end-1c")
        for tag in ("rule_keyword", "rule_string", "rule_number", "rule_comment"):
            widget.tag_remove(tag, "1.0", "end")

        kw = (r"\b(alert|drop|pass|reject|log|sid|msg|content|pcre|metadata|threshold|isdataat|"
              r"byte_test|flow|flowbits|fast_pattern|reference|classtype|priority|tag|http|tcp|udp|"
              r"icmp|any|any4|any6|established|notrack|flags|offset|depth|distance|within)\b")
        for m in re.finditer(kw, text, re.IGNORECASE):
            widget.tag_add("rule_keyword", f"1.0+{m.start()}c", f"1.0+{m.end()}c")
        for m in re.finditer(r'"(?:\\.|[^"\\])*"', text):
            widget.tag_add("rule_string", f"1.0+{m.start()}c", f"1.0+{m.end()}c")
        for m in re.finditer(r"\b0x[0-9A-Fa-f]+\b|\b\d+\b", text):
            widget.tag_add("rule_number", f"1.0+{m.start()}c", f"1.0+{m.end()}c")
        for m in re.finditer(r"(#.*?$|//.*?$)", text, re.MULTILINE):
            widget.tag_add("rule_comment", f"1.0+{m.start()}c", f"1.0+{m.end()}c")

    def validate_rule_text(self):
        rule_text_value = self.rule_builder_text.get("1.0", tk.END).strip()
        self.rule_preview_box.config(state=tk.NORMAL)
        self.rule_preview_box.delete("1.0", tk.END)

        if not rule_text_value:
            self.rule_preview_box.insert(tk.END, "Enter a Suricata rule to validate.\n")
            self.rule_preview_box.config(state=tk.DISABLED)
            return

        content_infos = parse_rule_contents(rule_text_value)
        pcre_values = self.suricata_parser.extract_pcre(rule_text_value)
        byte_tests = parse_rule_byte_tests(rule_text_value)
        isdataat_tests = parse_rule_isdataat(rule_text_value)
        metadata = parse_rule_metadata(rule_text_value)

        issues = []
        if not re.match(r"^\s*\w+\s+\w+\s+[^\s]+\s+[^\s]+\s+[^\s]+\s+[^\s]+\s*\(", rule_text_value):
            issues.append("Rule header may be malformed.")
        if not (content_infos or pcre_values or byte_tests or isdataat_tests):
            issues.append("Rule contains no content/pcre/byte_test/isdataat sections.")
        if pcre_values and any(not p for p in pcre_values):
            issues.append("One or more PCRE patterns appear empty.")

        self.rule_preview_box.insert(tk.END, f"Parsed metadata: {metadata}\n")
        self.rule_preview_box.insert(tk.END, f"Content sections: {len(content_infos)}\n")
        self.rule_preview_box.insert(tk.END, f"PCRE patterns: {len(pcre_values)}\n")
        self.rule_preview_box.insert(tk.END, f"byte_test rules: {len(byte_tests)}\n")
        self.rule_preview_box.insert(tk.END, f"isdataat sections: {len(isdataat_tests)}\n\n")

        if content_infos:
            self.rule_preview_box.insert(tk.END, "Content preview:\n")
            for item in content_infos:
                self.rule_preview_box.insert(
                    tk.END,
                    f"  - {item.get('content')} properties={item.get('properties')} negated={item.get('negated')}\n",
                )
            self.rule_preview_box.insert(tk.END, "\n")

        if issues:
            self.rule_preview_box.insert(tk.END, "Issues detected:\n", "issue")
            for issue in issues:
                self.rule_preview_box.insert(tk.END, f"  - {issue}\n", "issue")
        else:
            self.rule_preview_box.insert(tk.END, "Rule appears valid.\n", "valid")

        self.rule_preview_box.tag_configure("issue", foreground="#a00")
        self.rule_preview_box.tag_configure("valid", foreground="#1f7a1f")
        self.rule_preview_box.config(state=tk.DISABLED)

    def preview_current_rule(self):
        self.validate_rule_text()
        return parse_rule_threshold(self.rule_builder_text.get("1.0", tk.END).strip())

    # ------------------------------------------------------------------ #
    #  Payload generators                                                  #
    # ------------------------------------------------------------------ #

    def _format_payload_bytes(self, payload_bytes):
        mode = self.payload_output_mode.get()
        if mode == "hex":
            return " ".join(f"{b:02x}" for b in payload_bytes)
        if mode == "escaped":
            return "".join(f"\\x{b:02x}" for b in payload_bytes)
        return payload_bytes.decode("latin-1", errors="ignore")

    def _set_payload_text(self, payload_bytes):
        self.tester_payload_text.delete("1.0", tk.END)
        self.tester_payload_text.insert(tk.END, self._format_payload_bytes(payload_bytes))

    def generate_dns_payload(self):
        domain = b"www.example.com"
        header = bytes.fromhex("000001000001000000000000")
        qname = b"".join(len(p).to_bytes(1, "big") + p for p in domain.split(b".")) + b"\x00"
        self._set_payload_text(header + qname + bytes.fromhex("00010001"))

    def generate_sip_payload(self):
        self._set_payload_text((
            "INVITE sip:bob@example.com SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 192.168.0.1:5060;branch=z9hG4bK-1\r\n"
            "Max-Forwards: 70\r\nFrom: Alice <sip:alice@example.com>;tag=1234\r\n"
            "To: Bob <sip:bob@example.com>\r\nCall-ID: 123456@example.com\r\n"
            "CSeq: 1 INVITE\r\nContact: <sip:alice@192.168.0.1>\r\nContent-Length: 0\r\n\r\n"
        ).encode("latin-1"))

    def generate_http_payload(self):
        self._set_payload_text((
            "GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
            "User-Agent: Suricater/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        ).encode("latin-1"))

    def generate_shellcode_payload(self):
        self._set_payload_text(bytes([0x90, 0x90, 0x90, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC]))

    # ------------------------------------------------------------------ #
    #  Content box                                                         #
    # ------------------------------------------------------------------ #

    def render_content_box(self, content_infos, metadata=None, colorize=False):
        self.content_box.config(state=tk.NORMAL)
        self.content_box.delete("1.0", tk.END)
        self.selected_rule_content_infos = content_infos
        self.content_item_tag_map = {}
        contents = []

        if metadata:
            self.content_box.insert(tk.END, "Rule metadata:\n", "metaheader")
            for key in ('classtype', 'flow', 'flowbits', 'fast_pattern', 'tag', 'priority', 'metadata', 'reference'):
                value = metadata.get(key)
                if value:
                    self.content_box.insert(tk.END, f"{key}: {value}\n", "metakey")
            if metadata.get('other'):
                self.content_box.insert(tk.END, "other: " + str(metadata['other']) + "\n", "metakey")
            self.content_box.insert(tk.END, "\n")

        colors = ['black', 'blue', 'red', 'green', 'orange', 'violet']

        for idx, item in enumerate(content_infos):
            result_str = format_content_item(item)
            contents.append(result_str)
            tagname = f"content_item_{idx}"
            self.content_item_tag_map[tagname] = idx

            if colorize:
                parts = convert_hex_to_ascii(result_str).split(',')
                for i, part in enumerate(parts):
                    self.content_box.insert(
                        tk.END,
                        part + ("," if i < len(parts) - 1 else ""),
                        (colors[min(i, 5)], tagname),
                    )
                self.content_box.insert(tk.END, "\n", tagname)
            else:
                prefix = '[fast_pattern] ' if item.get('properties', {}).get('fast_pattern') else ''
                self.content_box.insert(tk.END, prefix + result_str + "\n", tagname)

            self.content_box.tag_bind(
                tagname, '<Button-1>', lambda e, t=tagname: self.toggle_content_fast_pattern(e, t))

        for color in colors:
            self.content_box.tag_config(color, foreground=color)
        self.content_box.config(state=tk.DISABLED)
        return "\n".join(contents)

    def toggle_content_fast_pattern(self, event, tagname):
        try:
            idx = self.content_item_tag_map.get(tagname)
            if idx is None or idx >= len(self.selected_rule_content_infos):
                return
            item = self.selected_rule_content_infos[idx]
            props = item.setdefault('properties', {})
            props['fast_pattern'] = not props.get('fast_pattern', False)
            self.render_content_box(self.selected_rule_content_infos)
        except Exception:
            return

    def get_content_in_ascii(self):
        self.input_text.tag_remove("highlight", "1.0", tk.END)
        selected_rule = self.rule_text.get("1.0", tk.END).strip()
        content_infos = parse_rule_contents(selected_rule)
        self.render_content_box(content_infos, colorize=True)
        if content_infos:
            self.check_content()

    # ------------------------------------------------------------------ #
    #  Rule selection                                                      #
    # ------------------------------------------------------------------ #

    def select_rule(self, event):
        idx = self.rule_combobox.current()
        page_offset = self.current_rule_page * self.rules_per_page
        absolute = page_offset + idx
        if idx == -1 or absolute >= len(self.filtered_rules):
            return

        selected_rule = self.filtered_rules[absolute]

        self.rule_text.config(state=tk.NORMAL)
        self.rule_text.delete("1.0", tk.END)
        self.rule_text.insert(tk.END, selected_rule)
        self.rule_text.tag_configure("center", justify='center')
        self.rule_text.yview_moveto(0.0)
        self.rule_text.tag_add("center", "1.0", "end")
        self.rule_text.config(state=tk.DISABLED)

        pcre_values = self.suricata_parser.extract_pcre(selected_rule)
        self.pcre_box.config(state=tk.NORMAL)
        self.pcre_box.delete("1.0", tk.END)
        self.pcre_box.insert(tk.END, "\n".join(pcre_values))
        self.pcre_box.tag_add("center", "1.0", "end")
        self.pcre_box.config(state=tk.DISABLED)

        content_infos = parse_rule_contents(selected_rule)
        metadata = parse_rule_metadata(selected_rule)
        self.selected_rule_content_infos = content_infos

        if content_infos:
            self.render_content_box(content_infos, metadata=metadata)
        else:
            self.content_box.config(state=tk.NORMAL)
            self.content_box.delete("1.0", tk.END)
            if any(metadata.values()):
                self.render_content_box([], metadata=metadata)
            else:
                self.content_box.insert(tk.END, "No content sections found in this rule.")
            self.content_box.config(state=tk.DISABLED)

        self.check_content()

    # ------------------------------------------------------------------ #
    #  Search & filter                                                     #
    # ------------------------------------------------------------------ #

    def filter_rules(self, search_text):
        q = search_text.lower().strip()
        if not q:
            return self.msg_values.copy(), self.rules.copy()
        msgs, rules = [], []
        for rule, lower in zip(self.rules, self.rules_lower):
            if q in lower:
                rules.append(rule)
                m = msg_pattern.search(rule)
                msgs.append(m.group(1) if m else "")
        return msgs, rules

    def update_combobox_options(self, search_text):
        self.filtered_msgs, self.filtered_rules = self.filter_rules(search_text)
        self.current_rule_page = 0
        self.update_rule_page()

    def perform_search(self, event=None):
        self.update_combobox_options(self.search_entry.get())

    # ------------------------------------------------------------------ #
    #  File loading                                                        #
    # ------------------------------------------------------------------ #

    def load_rules_in_background(self, file_path):
        local_rules, local_lower, local_msgs = [], [], []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as fh:
                for line_number, line in enumerate(fh, start=1):
                    if not sid_pattern.search(line):
                        continue
                    cleaned = line.lstrip('#').strip()
                    if not cleaned:
                        continue
                    local_rules.append(cleaned)
                    local_lower.append(cleaned.lower())
                    m = msg_pattern.search(cleaned)
                    if m:
                        local_msgs.append(m.group(1))
                    if line_number % 1000 == 0:
                        txt = f"Loading rules... {line_number} lines scanned"
                        self.root.after(0, lambda t=txt: self.loading_label.config(text=t))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror('Load Error', f'Could not load rules:\n{e}'))
            self.root.after(0, lambda: self.loading_label.config(text=''))
            return

        def finish():
            self.rules = local_rules
            self.rules_lower = local_lower
            self.msg_values = local_msgs
            self.filtered_rules = self.rules.copy()
            self.filtered_msgs = self.msg_values.copy()
            self.current_rule_page = 0
            self.update_rule_page()
            self.loading_label.config(text=f'Loaded {len(self.rules)} rules')

        self.root.after(0, finish)

    def choose_file_action(self):
        file_path = filedialog.askopenfilename(title="Choose a File")
        if file_path:
            self.loading_label.config(text='Starting load...')
            threading.Thread(target=self.load_rules_in_background, args=(file_path,), daemon=True).start()

    # ------------------------------------------------------------------ #
    #  Documentation & info                                                #
    # ------------------------------------------------------------------ #

    def open_documentation(self):
        docs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'suricata-latest'))
        if not os.path.isdir(docs_dir):
            messagebox.showerror('Documentation not found', f'Documentation folder not found:\n{docs_dir}')
            return
        html_files = [f for f in os.listdir(docs_dir) if f.lower().endswith('.html')]
        if not html_files:
            messagebox.showerror('Documentation not found', f'No HTML file found in:\n{docs_dir}')
            return
        webbrowser.open('file://' + os.path.join(docs_dir, html_files[0]))

    def show_info(self):
        win = tk.Toplevel(self.root)
        win.title("Info")
        win.geometry("400x350")

        tw = tk.Text(win, wrap="word", width=50, height=8)
        tw.pack(pady=10, padx=10)

        text = (
            "Suricater is a tool for signature analysis.\n"
            "Using Signatures and Choose - Load file with signatures.\n"
            "Using Signatures and Export - Download signatures based on a filter in the search bar.\n"
            "Use the Rule Tester tab to write custom rules and validate them against a payload."
        )
        base_font = font.Font(family="Helvetica", size=11)
        italic_font = font.Font(family="Helvetica", size=11, weight="bold", slant="italic")
        tw.configure(font=base_font)
        tw.insert("1.0", text)

        for word in ("Signatures", "Choose", "Export"):
            pos = "1.0"
            while True:
                pos = tw.search(word, pos, stopindex="end")
                if not pos:
                    break
                end = f"{pos}+{len(word)}c"
                tw.tag_add(word, pos, end)
                pos = end
            tw.tag_configure(word, font=italic_font)

        tw.config(state=tk.DISABLED)
        tw.tag_configure("center", justify='center')
        tw.tag_add("center", "1.0", "end")
        tk.Button(win, text="Close", command=win.destroy).pack(pady=10)

    # ------------------------------------------------------------------ #
    #  Tab switching                                                       #
    # ------------------------------------------------------------------ #

    def open_rule_tester_tab(self):
        self.signatures_frame.grid_remove()
        self.tester_frame.grid()

    def open_signatures_tab(self):
        self.tester_frame.grid_remove()
        self.signatures_frame.grid()

    def copy_rule_to_tester(self):
        text = self.rule_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Copy rule", "No selected rule is available to copy.")
            return
        self.rule_builder_text.config(state=tk.NORMAL)
        self.rule_builder_text.delete("1.0", tk.END)
        self.rule_builder_text.insert(tk.END, text)
        self.open_rule_tester_tab()

    # ------------------------------------------------------------------ #
    #  Payload content checking (signatures tab)                           #
    # ------------------------------------------------------------------ #

    def check_content(self, event=None):
        for tag in ("match_content", "match_pcre", "match_byte_test", "match_fast_pattern"):
            self.input_text.tag_remove(tag, "1.0", tk.END)

        payload = decode_payload_text(self.input_text.get("1.0", tk.END).strip())
        rule = self.rule_text.get("1.0", tk.END)

        content_infos = parse_rule_contents(rule)
        pcre_values = self.suricata_parser.extract_pcre(rule)
        byte_tests = parse_rule_byte_tests(rule)

        rule_ok, content_matches = match_rule_contents(payload, content_infos)
        pcre_matches, _ = match_rule_pcre(payload, pcre_values)
        _, byte_results = match_rule_byte_tests(payload, byte_tests, content_matches)

        if rule_ok:
            for m in content_matches:
                tag = "match_fast_pattern" if m['item'].get('properties', {}).get('fast_pattern') else "match_content"
                self.input_text.tag_add(tag, f"1.0+{m['start']}c", f"1.0+{m['end']}c")
        for m in pcre_matches:
            self.input_text.tag_add("match_pcre", f"1.0+{m['start']}c", f"1.0+{m['end']}c")
        for r in byte_results:
            if r['ok'] and r['span']:
                s, e = r['span']
                self.input_text.tag_add("match_byte_test", f"1.0+{s}c", f"1.0+{e}c")

        self.input_text.tag_config("match_content", background="yellow")
        self.input_text.tag_config("match_pcre", foreground="green", underline=1)
        self.input_text.tag_config("match_fast_pattern", background="#ffb84d")
        self.input_text.tag_config("match_byte_test", background="#ffcccb")
        return bool(content_matches), bool(pcre_matches)

    # ------------------------------------------------------------------ #
    #  Export                                                              #
    # ------------------------------------------------------------------ #

    def export_rules(self):
        q = self.search_entry.get().lower().strip()
        matching = (
            self.rules.copy() if not q
            else [r for r, lr in zip(self.rules, self.rules_lower) if q in lr]
        )
        if not matching:
            messagebox.showinfo("Export", "No matching rules found.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".rules",
                                             filetypes=[("Suricata Rules", "*.rules")])
        if path:
            try:
                with open(path, 'w') as fh:
                    fh.writelines(r + '\n' for r in matching)
                messagebox.showinfo("Export Successful", f"Rules exported to {path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"An error occurred: {e}")

    # ------------------------------------------------------------------ #
    #  Rule tester                                                         #
    # ------------------------------------------------------------------ #

    def test_rule(self):
        rule_text_value = self.rule_builder_text.get("1.0", tk.END).strip()
        payload_value = self.tester_payload_text.get("1.0", tk.END).strip()
        self.tester_result_box.config(state=tk.NORMAL)
        self.tester_result_box.delete("1.0", tk.END)
        for tag in ("match_content", "match_pcre", "match_byte_test", "match_fast_pattern", "match_isdataat"):
            self.tester_payload_text.tag_remove(tag, "1.0", tk.END)

        if not rule_text_value:
            messagebox.showinfo("Rule Tester", "Enter a Suricata rule to test.")
            self.tester_result_box.config(state=tk.DISABLED)
            return
        if not payload_value:
            messagebox.showinfo("Rule Tester", "Enter payload text to test against.")
            self.tester_result_box.config(state=tk.DISABLED)
            return

        payload_value = decode_payload_text(payload_value)
        content_infos = parse_rule_contents(rule_text_value)
        metadata = parse_rule_metadata(rule_text_value)
        pcre_values = self.suricata_parser.extract_pcre(rule_text_value)
        byte_tests = parse_rule_byte_tests(rule_text_value)
        isdataat_tests = parse_rule_isdataat(rule_text_value)

        rule_ok, content_matches = match_rule_contents(payload_value, content_infos)
        pcre_matches, invalid_patterns = match_rule_pcre(payload_value, pcre_values)
        byte_ok, byte_results = match_rule_byte_tests(payload_value, byte_tests, content_matches)
        isdataat_ok, isdataat_results = evaluate_isdataat(payload_value, isdataat_tests, content_matches)

        for m in content_matches:
            tag = "match_fast_pattern" if m['item'].get('properties', {}).get('fast_pattern') else "match_content"
            self.tester_payload_text.tag_add(tag, f"1.0+{m['start']}c", f"1.0+{m['end']}c")
        for m in pcre_matches:
            self.tester_payload_text.tag_add("match_pcre", f"1.0+{m['start']}c", f"1.0+{m['end']}c")
        for r in byte_results:
            if r['ok'] and r['span']:
                s, e = r['span']
                self.tester_payload_text.tag_add("match_byte_test", f"1.0+{s}c", f"1.0+{e}c")
        for r in isdataat_results:
            if r.get('ok') and r.get('span'):
                s, e = r['span']
                self.tester_payload_text.tag_add("match_isdataat", f"1.0+{s}c", f"1.0+{e}c")

        self.tester_payload_text.tag_config("match_content", background="#fff49c")
        self.tester_payload_text.tag_config("match_pcre", background="#c6f7c6")
        self.tester_payload_text.tag_config("match_fast_pattern", background="#ffb84d")
        self.tester_payload_text.tag_config("match_byte_test", background="#ffcccb")
        self.tester_payload_text.tag_config("match_isdataat", background="#d0e0ff")

        threshold_ok, threshold_info = rule_matches_threshold(rule_text_value, len(content_matches))
        fired = (rule_ok and bool(pcre_matches)) if pcre_values else rule_ok
        if not threshold_ok:
            fired = False

        pos_count = len([i for i in content_infos if not i.get('negated')])
        neg_count = len([i for i in content_infos if i.get('negated')])
        result_lines = [
            f"Rule tested: {pos_count} positive content section(s), {neg_count} negative content section(s), "
            f"{len(pcre_values)} PCRE pattern(s), {len(byte_tests)} byte_test(s), {len(isdataat_tests)} isdataat(s)"
        ]
        if metadata and any(metadata.values()):
            summary = [f"{k}={v}" for k, v in metadata.items() if v and k != 'other']
            if metadata.get('other'):
                summary.append(f"other={metadata['other']}")
            result_lines.append("Parsed metadata: " + ", ".join(summary))

        result_lines += [
            f"Content sequence match: {'yes' if rule_ok else 'no'}",
            f"PCRE sequence match: {'yes' if pcre_matches else 'no'}",
            f"byte_test match: {'yes' if byte_ok else 'no'}",
            f"isdataat match: {'yes' if isdataat_ok else 'no'}",
        ]
        for r in isdataat_results:
            t = r['test']
            result_lines.append(
                f"  - isdataat: count={t.get('count')} relative={t.get('relative')} "
                f"available={r.get('available')} ok={r.get('ok')}"
            )
        if threshold_info:
            result_lines.append(f"Threshold configured: {threshold_info}")
            result_lines.append(
                f"Threshold satisfied: {'yes' if threshold_ok else 'no'} (count {threshold_info.get('count', '1')})"
            )

        fired_line = f"Rule fired: {'yes' if fired else 'no'}"
        result_lines.append(fired_line)

        if invalid_patterns:
            result_lines.append("Invalid PCRE patterns:")
            result_lines += [f"  - {p}" for p in invalid_patterns]

        self.tester_result_box.insert(tk.END, "\n".join(result_lines))

        color = "#1f7a1f" if fired else "#a00"
        tag = "fired" if fired else "notfired"
        self.tester_result_box.tag_configure(tag, foreground=color)
        start = self.tester_result_box.search("Rule fired:", "1.0", stopindex="end")
        if start:
            self.tester_result_box.tag_add(tag, start, f"{start}+{len(fired_line)}c")

        self.tester_result_box.config(state=tk.DISABLED)

    # ------------------------------------------------------------------ #
    #  Rule generator                                                      #
    # ------------------------------------------------------------------ #

    def generate_rule(self):
        action = self.action_entry.get().strip() or 'alert'
        proto = self.proto_entry.get().strip() or 'tcp'
        src_ip = self.src_ip_entry.get().strip() or 'any'
        src_port = self.src_port_entry.get().strip() or 'any'
        direction = self.direction_combo.get().strip() or '->'
        dst_ip = self.dst_ip_entry.get().strip() or 'any'
        dst_port = self.dst_port_entry.get().strip() or 'any'
        msg = self.msg_entry.get().strip() or 'generated rule'
        sid = self.sid_entry.get().strip() or '1000001'
        content_value = self.content_entry.get().strip()
        pcre_value = self.pcre_entry.get().strip()

        options = [f'msg:"{msg}"', f'sid:{sid}']
        if content_value:
            options.append(f'content:"{content_value}"')
        if pcre_value:
            options.append(f'pcre:"{pcre_value}"')

        rule = f"{action} {proto} {src_ip} {src_port} {direction} {dst_ip} {dst_port} ({'; '.join(options)};)"
        self.rule_builder_text.config(state=tk.NORMAL)
        self.rule_builder_text.delete("1.0", tk.END)
        self.rule_builder_text.insert(tk.END, rule)
        self.open_rule_tester_tab()

    def save_generated_rule(self):
        rule = self.rule_builder_text.get("1.0", tk.END).strip()
        if not rule:
            messagebox.showinfo("Save Rule", "No rule text available to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".rules",
                                             filetypes=[("Suricata Rules", "*.rules")])
        if not path:
            return
        try:
            with open(path, 'a', encoding='utf-8') as fh:
                fh.write(rule + '\n')
            messagebox.showinfo("Save Rule", f"Rule saved to {path}")
        except Exception as e:
            messagebox.showerror("Save Rule", f"Could not save rule: {e}")

    def convert_ascii_button_action(self):
        self.select_rule(None)
        self.check_content()
