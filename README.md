# 🛡️ Wazuh Rule Visualizer

Check a Wazuh ruleset before it reaches the manager, clean it up, and see how the
rules actually chain together.

[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://blank-app-template.streamlit.app/)

Load any file from `/var/ossec/etc/rules/` and you get three things:

1. **A health check** — everything that would stop `wazuh-manager` from loading
   the file, or leave a rule that can never fire, each with the fix.
2. **A cleaned XML file** — encoding, bare `&`, illegal `--` in comments, tabs,
   trailing whitespace, group commas and indentation, repaired and downloadable.
3. **A relationship graph** — `if_sid` chains laid out as a hierarchy, with
   focus mode, per-link-type colours and a legend that says what they mean.

---

## What the health check finds

Findings are graded by what they cost you.

**Errors — the manager rejects the file, or the rule can never fire**

| Code | Finding |
| --- | --- |
| `WZ002` | Unescaped `&` in text |
| `WZ006` / `WZ007` | Illegal `--` inside a comment, or an unterminated comment |
| `WZ020` | XML is not well-formed, reported with the line, column and surrounding source |
| `WZ030` | Root element is not `<group>` |
| `WZ040` | `type="pcre2"` pattern that does not compile |
| `WZ050`–`WZ055` | Missing / non-numeric / out-of-range rule `id` or `level` |
| `WZ061` / `WZ062` | Missing or empty `<description>` |
| `WZ064` / `WZ065` / `WZ066` | `<field>` with no `name`, `<list>` with no `field`/`lookup`/path |
| `WZ068`–`WZ078` | `<frequency>` with no `<timeframe>`, non-numeric values |
| `WZ073` / `WZ074` | Empty or non-numeric `if_sid` / `if_matched_sid` |
| `WZ075` | A rule that lists itself as its own parent |
| `WZ080` | Duplicated rule id — the classic "manager will not start" |
| `WZ083` | Circular `if_sid` chain |

**Warnings — it loads, but probably does not do what you meant**

| Code | Finding |
| --- | --- |
| `WZ041` | Regex metacharacters inside `<match>`, which is a literal substring test |
| `WZ042` | PCRE-only syntax (`(?i)`, `\b`, `{2,5}`, `[a-z]`, lazy quantifiers) handed to OS_Regex without `type="pcre2"`, so the rule silently never matches |
| `WZ056` | Rule id below 100000, inside Wazuh's reserved range |
| `WZ058` / `WZ059` | Unknown attribute or misspelled tag (`<discription>`, `<if_sids>`) |
| `WZ067` | Unknown value in `<options>` |
| `WZ070` / `WZ071` / `WZ072` | `frequency` below 2, with no `if_matched_*` anchor, or a `timeframe` with nothing to count |
| `WZ077` | A rule with no condition at all — it is evaluated against every event |
| `WZ081` | `if_sid` pointing at a rule that is not in this file |

**Info** — BOM, CRLF, tabs, trailing whitespace, missing XML declaration,
missing trailing commas on group names, deprecated `<same_source_ip>`-style tags.

Every finding carries a `How to fix` line. Download the whole thing as a text
report from the Health check tab.

## What Clean XML does

Only mechanical repairs. It never rewrites detection logic — your `level`, `id`,
regex patterns and descriptions come out exactly as you wrote them.

- strips a UTF-8 BOM, converts CRLF to LF, replaces tabs
- escapes bare `&` as `&amp;` (leaving existing entities alone, and never
  touching the inside of comments)
- collapses the illegal `--` sequences inside XML comments
- strips trailing whitespace, adds the XML declaration
- adds the conventional trailing comma to group names
- wraps a file whose root is not `<group>`
- reindents to two spaces, keeping a blank line between rules

Untick **"Also reindent and normalise"** to keep your original formatting byte
for byte and only fix the characters that break the parser.

When a file has a syntax error, the app cleans it first and then re-runs the
deeper checks, so one bad `&` on line 4 does not hide a duplicate rule id on
line 200.

## Reading the graph

- **Layout** — *Hierarchy* puts parents above children, which is the one to use
  for `if_sid` chains. *Clustered by group* is better for spotting which group
  owns which rules.
- **Node colour and size** follow the Wazuh level: red critical (10-16), orange
  high (7-9), yellow medium (4-6), green low (1-3), grey ignored (0).
- **Hollow grey nodes** are rules referenced by `if_sid` that this file does not
  define. If they exist in Wazuh's bundled ruleset the chain works; if not,
  every child of them is dead code.
- **Link colours**: blue `if_sid`, pink `if_matched_sid`, green
  `if_matched_group`, amber `if_group`. Click a legend entry to hide that type.
- **Focus on a rule** dims everything outside that rule's ancestors and
  descendants, and draws its trigger chain underneath as a single line.

## Running it locally

Python 3.9 or newer (the cleaner uses `xml.etree.ElementTree.indent`).

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

Then open http://localhost:8501.

## Deploying to Streamlit Community Cloud

The repo is ready to deploy as-is.

1. Push it to GitHub.
2. At [share.streamlit.io](https://share.streamlit.io) pick **New app**, choose
   this repo and branch, and set the main file to `streamlit_app.py`.
3. Under **Advanced settings**, choose **Python 3.11** (anything 3.9+ works).
4. Deploy.

What makes it host-ready:

- `requirements.txt` pins every dependency to a major-version range, so a
  surprise upstream release cannot break a redeploy.
- `.streamlit/config.toml` carries the theme, a 20 MB upload cap, XSRF
  protection on, and `showErrorDetails = false` so tracebacks stay in the server
  log instead of the browser.
- The app never writes to disk. Everything is held in session state, and parsing,
  linting and cleaning are memoised with `@st.cache_data`.
- Uploads are size-checked and decoded defensively, so a non-UTF-8 or oversized
  file gives a clear message instead of a stack trace.
- No secrets, no network calls, no database.

## Deploying the rules to a Wazuh manager

```bash
# 1. copy the cleaned file onto the manager
scp cleaned_rules.xml manager:/var/ossec/etc/rules/local_rules.xml

# 2. validate the whole ruleset before restarting anything
/var/ossec/bin/wazuh-logtest -t

# 3. restart and watch
systemctl restart wazuh-manager
tail -f /var/ossec/logs/ossec.log
```

If the manager will not start, it is almost always one of the blocking errors
above: a duplicated rule id, a missing description, an `if_sid` pointing at a
rule that does not exist, or invalid XML.

## Project layout

```
streamlit_app.py            the Streamlit UI
wazuh_parser.py             XML -> RuleData, detection cues, filter conditions
wazuh_linter.py             the checks, the recommendations and the cleaner
severity.py                 one source of truth for level -> label/colour/size
visualizations/flowchart.py the relationship graph
visualizations/analytics.py treemap, severity bar, MITRE coverage, chain view
test_wazuh_linter.py        33 tests over the linter and cleaner
```

## Tests

```bash
python3 test_wazuh_linter.py     # linter and cleaner
python3 test_wazuh_parser.py     # parser
for f in test_*.py; do python3 "$f" >/dev/null && echo "ok $f"; done
```

## Contributing

Focus on modular components — parsers, Plotly traces, new lint checks. A new
check is a function that appends a `LintIssue` with a `recommendation`; that
field is not optional, a finding without a fix is not worth showing.
