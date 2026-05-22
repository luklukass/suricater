# Minimal tests for byte_test parsing and evaluation
import sys

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

import re

def parse_rule_byte_tests(rule_text):
    tests = []
    for opt in [s.strip() for s in rule_text.split(';') if s.strip()]:
        cleaned = opt.strip()
        if cleaned.startswith('byte_test:'):
            params = [p.strip() for p in cleaned.split(':', 1)[1].split(',') if p.strip()]
            if len(params) < 4:
                continue
            size = parse_int_value(params[0])
            operator = params[1].lower()
            value = parse_int_value(params[2])
            offset = parse_int_value(params[3])
            raw_options = params[4:]
            options = [p.lower() for p in raw_options]
            relative = 'relative' in options
            endian = 'little' if 'little' in options else 'big'
            signed = 'signed' in options
            mask = None
            for optpart in raw_options:
                if optpart.lower().startswith('mask') and ':' in optpart:
                    try:
                        mask = parse_int_value(optpart.split(':', 1)[1])
                    except Exception:
                        mask = None
                elif optpart.lower().startswith('mask') and '=' in optpart:
                    try:
                        mask = parse_int_value(optpart.split('=', 1)[1])
                    except Exception:
                        mask = None
                else:
                    if re.match(r'^0x[0-9a-fA-F]+$', optpart):
                        try:
                            mask = parse_int_value(optpart)
                        except Exception:
                            pass
            tests.append({
                'size': size,
                'operator': operator,
                'value': value,
                'offset': offset,
                'relative': relative,
                'endian': endian,
                'signed': signed,
                'mask': mask,
            })
    return tests


def evaluate_byte_test(payload, test, content_matches):
    payload_bytes = payload if isinstance(payload, (bytes, bytearray)) else payload.encode('latin-1', errors='ignore')
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
    mask = test.get('mask')
    if mask is not None:
        try:
            mask_val = int(mask)
        except Exception:
            mask_val = None
    else:
        mask_val = None

    if mask_val is not None and op not in ('&', 'and'):
        comp_value = value & mask_val
    else:
        comp_value = value

    if op in ('&', 'and'):
        if mask_val is None:
            result = (value & target) == target
        else:
            result = (value & mask_val) == target
    elif op in ('>', 'gt'):
        result = comp_value > target
    elif op in ('<', 'lt'):
        result = comp_value < target
    elif op in ('==', '=', 'eq'):
        result = comp_value == target
    elif op in ('!=', 'ne'):
        result = comp_value != target
    elif op in ('>=', 'ge'):
        result = comp_value >= target
    elif op in ('<=', 'le'):
        result = comp_value <= target
    return result, (offset, offset + test['size'])


def run_tests():
    tests = []
    # 1: big-endian equality
    rule1 = 'byte_test: 2, ==, 0x4142, 0'
    payload1 = b'AB'
    tests.append((rule1, payload1, True))
    # 2: little-endian equality
    rule2 = 'byte_test: 2, ==, 0x4241, 0, little'
    payload2 = b'AB'
    tests.append((rule2, payload2, True))
    # 3: mask with explicit mask and & operator
    rule3 = 'byte_test: 4, &, 0x00220000, 0, mask:0x00FF0000'
    payload3 = bytes([0x11,0x22,0x33,0x44])
    tests.append((rule3, payload3, True))
    # 4: & operator with target used as mask
    rule4 = 'byte_test: 4, &, 0x00220000, 0'
    payload4 = bytes([0x11,0x22,0x33,0x44])
    tests.append((rule4, payload4, True))
    # 5: signed comparison (negative) - 1 byte signed equals -1
    rule5 = 'byte_test: 1, ==, -1, 0, signed'
    payload5 = bytes([0xFF])
    tests.append((rule5, payload5, True))
    # 6: relative offset: simulate a content match ending at 2, so offset=1 relative -> checks at 3
    rule6 = 'byte_test: 1, ==, 0x33, 1, relative'
    payload6 = bytes([0x11,0x22,0x33,0x44])
    # will pass when last content end is 2 -> offset 3rd byte (0-based index 2)
    tests.append((rule6, payload6, True, [{'start':0,'end':1}]))

    # isdataat tests
    isdata_tests = []
    # isdataat: 2 bytes available at offset 1 (not relative)
    isdata_tests.append(('isdataat: 2', bytes([0x11,0x22,0x33]), True))
    # isdataat relative: require 2 bytes after last content end
    isdata_tests.append(('isdataat: 2, relative', bytes([0x11,0x22,0x33,0x44]), True, [{'start':0,'end':2}]))

    all_ok = True
    for idx, entry in enumerate(tests, 1):
        if len(entry) == 3:
            rule, payload, expected = entry
            content_matches = []
        else:
            rule, payload, expected, content_matches = entry
        parsed = parse_rule_byte_tests(rule)
        if not parsed:
            print(f"Test {idx}: failed to parse rule: {rule}")
            all_ok = False
            continue
        ok, span = evaluate_byte_test(payload, parsed[0], content_matches if 'content_matches' in locals() else [])
        print(f"Test {idx}: rule={rule} expected={expected} got={ok} span={span}")
        if ok != expected:
            all_ok = False
    if all_ok:
        print("ALL TESTS PASS")
        return 0
    else:
        print("SOME TESTS FAILED")
        return 2

if __name__ == '__main__':
    sys.exit(run_tests())
