# Suricater

Tool for Suricata signature analysis.
The official documentation is also included.

## New Rule Builder & Tester

The GUI now includes a dedicated `Rule Tester` tab next to `Signatures`.

- Create or paste custom Suricata rules in the `Rule text` editor.
- Use the generator fields to build a rule from action, protocol, IPs, ports, `msg`, `sid`, `content`, and `pcre`.
- Save generated rules with `Save Rule` into a `.rules` file.
- Enter the payload to test against in `Test payload`.
- Click `Test Rule` to validate content and PCRE matches.
- Use the `Copy selected rule` menu item to load a selected signature into the tester.

## Usage

1. Load rules from a file using `Signatures -> Choose`.
2. Select a rule from the dropdown to inspect its `content` and `pcre` sections.
3. Switch to `Rule Tester` to author and validate new rules manually.

