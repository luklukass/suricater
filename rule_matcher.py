import re

from rule_parser import (
    parse_suricata_pcre, decode_suricata_string, convert_hex_to_ascii, parse_rule_threshold,
)


def find_content_match(payload, content_item, search_start, search_end):
    pattern = decode_suricata_string(convert_hex_to_ascii(content_item['content']))
    if not pattern:
        return None
    flags = re.IGNORECASE if content_item['properties'].get('nocase') else 0
    try:
        regex = re.compile(re.escape(pattern), flags)
    except re.error:
        return None
    match = regex.search(payload[search_start:search_end])
    if not match:
        return None
    return search_start + match.start(), search_start + match.end()


def match_rule_contents(payload, content_infos):
    matches = []
    last_end = 0

    for index, item in enumerate(content_infos):
        props = item['properties']

        if item.get('negated'):
            negated_text = convert_hex_to_ascii(item['content'])
            flags = re.IGNORECASE if props.get('nocase') else 0
            if re.search(re.escape(negated_text), payload, flags):
                return False, []
            continue

        def _int(key, default=None):
            v = props.get(key)
            if v is not None and str(v).lstrip('-').isdigit():
                return int(v)
            return default

        offset = _int('offset')
        depth = _int('depth')
        distance = _int('distance', 0)
        within = _int('within')

        if index == 0:
            search_start = offset if offset is not None else 0
            search_end = min(search_start + depth, len(payload)) if depth is not None else len(payload)
        else:
            search_start = last_end + distance
            if within is not None:
                search_end = min(search_start + within, len(payload))
            elif depth is not None:
                search_end = min(search_start + depth, len(payload))
            else:
                search_end = len(payload)

        if not (0 <= search_start <= len(payload)):
            return False, []

        span = find_content_match(payload, item, search_start, search_end)
        if not span:
            return False, []

        matches.append({'start': span[0], 'end': span[1], 'item': item})
        last_end = span[1]

    return True, matches


def match_rule_pcre(payload, pcre_values):
    matches = []
    invalid = []
    for raw_pattern in pcre_values:
        pattern, flags = parse_suricata_pcre(raw_pattern)
        try:
            regex = re.compile(pattern, flags)
            for m in regex.finditer(payload):
                matches.append({'start': m.start(), 'end': m.end(), 'pattern': raw_pattern})
        except re.error:
            invalid.append(raw_pattern)
    return matches, invalid


def evaluate_byte_test(payload, test, content_matches):
    if any(test[k] is None for k in ('size', 'value', 'offset')):
        return False, None

    payload_bytes = payload.encode('latin-1', errors='ignore')
    last_end = content_matches[-1]['end'] if content_matches else 0
    offset = test['offset'] + (last_end if test['relative'] else 0)

    if not (0 <= offset and offset + test['size'] <= len(payload_bytes)):
        return False, None

    try:
        value = int.from_bytes(
            payload_bytes[offset:offset + test['size']],
            byteorder=test.get('endian', 'big'),
            signed=test.get('signed', False),
        )
    except OverflowError:
        return False, None

    op = test['operator']
    target = test['value']
    mask_val = int(test['mask']) if test.get('mask') is not None else None
    comp = (value & mask_val) if (mask_val is not None and op not in ('&', 'and')) else value

    if op in ('&', 'and'):
        result = ((value & target) == target) if mask_val is None else ((value & mask_val) == target)
    elif op in ('>', 'gt'):
        result = comp > target
    elif op in ('<', 'lt'):
        result = comp < target
    elif op in ('==', '=', 'eq'):
        result = comp == target
    elif op in ('!=', 'ne'):
        result = comp != target
    elif op in ('>=', 'ge'):
        result = comp >= target
    elif op in ('<=', 'le'):
        result = comp <= target
    else:
        result = False

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
        base = content_matches[-1]['end'] if (test['relative'] and content_matches) else 0
        available = len(payload) - base
        ok = available >= required
        span = (base, base + required) if required else (base, len(payload))
        results.append({'test': test, 'ok': ok, 'available': available, 'span': span})
        if not ok:
            return False, results
    return True, results


def rule_matches_threshold(rule_text, content_match_count):
    threshold = parse_rule_threshold(rule_text)
    if not threshold:
        return True, None
    count_str = threshold.get('count', '1')
    count = int(count_str) if str(count_str).isdigit() else 1
    if content_match_count < count:
        return False, threshold
    return True, threshold
