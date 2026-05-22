import re

sid_pattern = re.compile(r'\bsid\b')
msg_pattern = re.compile(r'msg:"([^"]*)"')


class SuricataRuleParser:
    def __init__(self):
        self.keyword_pcre = re.compile(r'pcre:\s*"((?:\\.|[^"\\])*)"')

    def extract_pcre(self, rule_text):
        pcre = self.keyword_pcre.findall(rule_text)
        return [p.replace('\\"', '"') for p in pcre]


def hex_to_ascii(match):
    hex_string = match.group(1).replace("|", "")
    ascii_string = ""
    for hex_value in hex_string.split():
        try:
            ascii_string += chr(int(hex_value, 16))
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
    body = rule_text[start + 1:end]
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
    return re.sub(r'\\x([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), decoded)


def parse_suricata_pcre(raw_pattern):
    pcre = raw_pattern.strip()
    if len(pcre) >= 2 and pcre[0] == '/' and '/' in pcre[1:]:
        end = pcre.rfind('/')
        pattern = pcre[1:end]
        flags_str = pcre[end + 1:]
        re_flags = 0
        if 'i' in flags_str:
            re_flags |= re.IGNORECASE
        if 'm' in flags_str:
            re_flags |= re.MULTILINE
        if 's' in flags_str:
            re_flags |= re.DOTALL
        if 'x' in flags_str:
            re_flags |= re.VERBOSE
        return pattern, re_flags
    return pcre, 0


def decode_payload_text(payload):
    if not payload:
        return payload
    return re.sub(r'\\x([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), payload)


def parse_int_value(value_text):
    value_text = value_text.strip()
    if not value_text:
        return None
    try:
        if value_text.startswith(('0x', '0X')):
            return int(value_text, 16)
        return int(value_text, 10)
    except ValueError:
        return None


def parse_rule_byte_tests(rule_text):
    tests = []
    for opt in split_rule_options(rule_text):
        cleaned = opt.strip()
        if not cleaned.startswith('byte_test:'):
            continue
        params = [p.strip() for p in cleaned.split(':', 1)[1].split(',') if p.strip()]
        if len(params) < 4:
            continue
        raw_options = params[4:]
        options_lower = [p.lower() for p in raw_options]
        mask = None
        for optpart in raw_options:
            ol = optpart.lower()
            if ol.startswith('mask') and ':' in optpart:
                mask = parse_int_value(optpart.split(':', 1)[1])
            elif ol.startswith('mask') and '=' in optpart:
                mask = parse_int_value(optpart.split('=', 1)[1])
            elif re.match(r'^0x[0-9a-fA-F]+$', optpart):
                mask = parse_int_value(optpart)
        tests.append({
            'size': parse_int_value(params[0]),
            'operator': params[1].lower(),
            'value': parse_int_value(params[2]),
            'offset': parse_int_value(params[3]),
            'relative': 'relative' in options_lower,
            'endian': 'little' if 'little' in options_lower else 'big',
            'signed': 'signed' in options_lower,
            'mask': mask,
        })
    return tests


def parse_rule_isdataat(rule_text):
    isdataat = []
    for opt in split_rule_options(rule_text):
        cleaned = opt.strip()
        if not cleaned.startswith('isdataat:'):
            continue
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
    skip_prefixes = ('content:', 'content:!', 'rawbytes:', 'pcre:', 'byte_test:', 'isdataat:', 'threshold:')
    for opt in split_rule_options(rule_text):
        cleaned = opt.strip()
        if not cleaned or cleaned.startswith(skip_prefixes) or ':' not in cleaned:
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


def parse_rule_contents(rule_text):
    content_infos = []
    current_item = None

    for opt in split_rule_options(rule_text):
        cleaned = opt.strip()
        if not cleaned:
            continue

        if cleaned.startswith('content:!'):
            if current_item is not None:
                content_infos.append(current_item)
            m = re.match(r'content:!\s*"((?:\\.|[^"\\])*)"', cleaned)
            raw = m.group(1) if m else cleaned.split(':!', 1)[1]
            current_item = {'content': cleanup_suricata_value(f'"{raw}"' if m else raw), 'properties': {}, 'negated': True}
            continue

        if cleaned.startswith('rawbytes:'):
            if current_item is not None:
                content_infos.append(current_item)
            m = re.match(r'rawbytes:\s*"((?:\\.|[^"\\])*)"', cleaned)
            raw = m.group(1) if m else cleaned.split(':', 1)[1]
            current_item = {'content': cleanup_suricata_value(f'"{raw}"' if m else raw), 'properties': {'rawbytes': True}, 'negated': False}
            continue

        if cleaned.startswith('content:'):
            if current_item is not None:
                content_infos.append(current_item)
            m = re.match(r'content:\s*"((?:\\.|[^"\\])*)"', cleaned)
            raw = m.group(1) if m else cleaned.split(':', 1)[1]
            current_item = {'content': cleanup_suricata_value(f'"{raw}"' if m else raw), 'properties': {}, 'negated': False}
            continue

        if current_item is None:
            continue

        if cleaned == 'nocase':
            current_item['properties']['nocase'] = True
            continue

        if cleaned == 'fast_pattern':
            current_item['properties']['fast_pattern'] = True
            continue

        if ':' in cleaned:
            key, value = cleaned.split(':', 1)
            key = key.strip()
            current_item['properties'][key] = cleanup_suricata_value(value)
            if key == 'reference':
                content_infos.append(current_item)
                current_item = None

    if current_item is not None:
        content_infos.append(current_item)
    return content_infos


def parse_rule_threshold(rule_text):
    m = re.search(r'threshold:\s*([^;]+)', rule_text)
    if not m:
        return {}
    threshold = {}
    for part in m.group(1).split(','):
        part = part.strip()
        if not part:
            continue
        km = re.match(r'(\w+)\s*[: ]\s*(.+)', part)
        if km:
            threshold[km.group(1)] = km.group(2).strip()
    return threshold


def format_content_item(content_item):
    content = content_item['content']
    props = content_item['properties']
    negated = content_item.get('negated', False)
    return (
        f"{content}, negated: {negated}, rawbytes: {props.get('rawbytes', False)}, "
        f"distance: {props.get('distance', 'None')}, offset: {props.get('offset', 'None')}, "
        f"within: {props.get('within', 'None')}, depth: {props.get('depth', 'None')}, "
        f"nocase: {props.get('nocase', False)}"
    )
