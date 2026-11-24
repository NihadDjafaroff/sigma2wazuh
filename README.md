# sigma2wazuh

![Tests](https://img.shields.io/badge/tests-21%20passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

A command-line tool that converts [Sigma](https://github.com/SigmaHQ/sigma) detection
rules (the vendor-neutral YAML format used across the SOC/detection-engineering
community) into [Wazuh](https://wazuh.com/) `local_rules.xml` rules.

## Why

Sigma rules are the closest thing the detection-engineering world has to a common
language for "what does this attack technique look like in logs." Wazuh, however,
needs its own XML rule syntax. Teams running Wazuh either hand-translate public Sigma
content rule-by-rule, or skip it entirely. This tool automates the mechanical part of
that translation — field matching, modifiers (`contains`, `startswith`, `endswith`,
`re`, `all`), boolean conditions (`and`/`or`/`not`, `1 of`/`all of`), MITRE ATT&CK tags,
and severity-level mapping — so an analyst can focus on validating the output against
real logs instead of writing XML by hand.

## Install

```bash
git clone https://github.com/NihadDjafaroff/sigma2wazuh.git
cd sigma2wazuh
pip install -r requirements.txt
```

No packaging/installation step is required beyond PyYAML — run it as a module.

To run the test suite, install the dev dependencies as well:
```bash
pip install -r requirements-dev.txt
python3 -m pytest tests/ -v
```

## Usage

Convert a single rule, print to stdout:
```bash
python3 -m sigma2wazuh convert examples/suspicious_powershell_download.yml
```

Convert a single rule to a file, with a custom starting rule ID:
```bash
python3 -m sigma2wazuh convert examples/suspicious_lsass_access.yml \
    -o output/local_rules_from_sigma.xml --start-id 100100
```

Convert every rule in a directory into one `local_rules.xml`, with sequential,
non-colliding rule IDs:
```bash
python3 -m sigma2wazuh convert-dir examples/ -o output/local_rules_from_sigma.xml
```

### Example

Input (`examples/suspicious_powershell_download.yml`):
```yaml
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: ['DownloadString', 'Invoke-WebRequest', 'IEX']
  condition: selection
level: high
tags: [attack.execution, attack.t1059.001]
```

Output:
```xml
<group name="sigma_converted,">

  <rule id="100100" level="12">
    <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(?:DownloadString|Invoke\-WebRequest|IEX)</field>
    <description>Suspicious PowerShell Download Command</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

</group>
```

## What it handles

- Field modifiers: plain (exact match), `contains`, `startswith`, `endswith`, `re`
  (raw regex), and `all` (every value in a list must match, instead of any one).
- Boolean conditions: `selection`, `a and b [and c ...]`, `a or b [or c ...]`,
  `not selection`, `a and not b`, `1 of them` / `all of them`,
  `1 of sel_*` / `all of sel_*` (wildcard prefix).
- List-style selections (`selection: [ {..}, {..} ]`), treated as an OR of AND-blocks.
- MITRE ATT&CK technique IDs pulled from `tags: [attack.t1059.001, ...]`.
- Sigma severity levels mapped to Wazuh's 0–15 scale.
- Automatic, non-colliding rule ID allocation across a whole directory of rules.

## What it deliberately does not handle

Wazuh's `<rule>` XML can only express an **AND** of its child `<field>` elements —
there is no native "OR" inside one rule. When a Sigma condition resolves to an OR at
the top level (`a or b`, a list-style selection, `1 of them`), this tool emits
**multiple sibling rules** (one per OR branch, with sequential IDs) and prints a
warning so you know to expect more than one `<rule>` per Sigma file. This is the
correct and only way to express that OR in Wazuh, but it does mean the alert count
and rule IDs don't map 1:1 to Sigma rule files.

Not supported, and will raise a clear error rather than silently producing a wrong
rule:
- Mixing `and`/`or` in the same condition without parentheses (ambiguous).
- `not` applied to anything other than a single-field selection.
- Sigma modifiers beyond `contains`/`startswith`/`endswith`/`re`/`all`
  (e.g. `base64offset`, `cidr`, `fieldref`).
- Correlation rules (Sigma's newer multi-event `correlation` rule type).

**Field-name mapping is a best-effort default** (`field_map.py`), based on common
Wazuh Windows-eventchannel decoding (`win.eventdata.*`). The exact field name
available in any real Wazuh deployment depends on the active decoder/ruleset
version. Always validate generated rules against real log samples with
`wazuh-logtest` before deploying to production — this tool produces a strong
first draft, not a drop-in-and-trust artifact.

## Project structure

```
sigma2wazuh/
├── sigma2wazuh/
│   ├── sigma_parser.py    # load + validate Sigma YAML
│   ├── detection.py       # Sigma condition logic -> OR-of-AND-groups
│   ├── field_map.py       # Sigma field name -> Wazuh field name
│   ├── wazuh_writer.py    # OR-of-AND-groups -> Wazuh <rule> XML
│   ├── converter.py       # top-level convert_file / convert_directory API
│   └── cli.py             # command-line interface
├── examples/              # sample Sigma rules used in the README and tests
├── tests/                 # pytest suite (21 tests)
└── output/                # generated XML lands here (gitignored except .gitkeep)
```

## Testing

```bash
pip install pytest
python3 -m pytest tests/ -v
```

## Background

Written as a portfolio project connecting prior SOC/Wazuh experience with
detection-engineering practice: Sigma is the format most public threat-detection
content (and most job postings) reference, while Wazuh is the SIEM used day-to-day.

## License

[MIT](LICENSE)
