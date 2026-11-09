#!/usr/bin/env python3
"""Builds res/PolicyCsp.tsv.gz, the offline Policy CSP catalog, from Microsoft's Policy CSP documentation.

The input is a checkout of the Windows client documentation (MicrosoftDocs/windows-itpro-docs or a fork of it),
or its windows/client-management/mdm folder. Every policy-csp-<area>.md file is parsed into one row per policy:
area, name, scope, friendly name, short description, format, default, range, allowed values with their meaning,
and the Group Policy (ADMX) mapping with registry key and value name.

Usage:
    python3 tools/build_csp_catalog.py <docs checkout or mdm folder> [-o res/PolicyCsp.tsv.gz]

The output is reproducible: rows are sorted and the gzip header carries no time stamp or file name.
Only the Python standard library is used.
"""

import argparse
import collections
import glob
import gzip
import html
import io
import os
import re
import subprocess
import sys

FORMAT = "PolicyVice Policy CSP catalog 1"
UPSTREAM = "https://github.com/MicrosoftDocs/windows-itpro-docs"
LICENSE = "CC BY 4.0, Microsoft Corporation and contributors"
COLUMNS = [
    "Area", "Name", "Scope", "FriendlyName", "Description", "Format", "Default", "Range", "Values",
    "AdmxBacked", "AdmxFile", "AdmxPolicy", "GpPath", "GpLocation", "GpElement", "GpKey", "GpValueName",
]
MAX_DESCRIPTION = 400
MAX_MEANING = 160
SHORT_MEANING = 100

RX_SECTION = re.compile(r"<!--\s*(\S+?)-(Applicability|OmaUri|Description|Editable|DFProperties|AllowedValues|GpMapping|AdmxBacked)-Begin\s*-->(.*?)<!--\s*\1-\2-End\s*-->", re.S)
RX_OMA = re.compile(r"\./(Device|User)/Vendor/MSFT/Policy/Config/([^/\s`]+)/([^/\s`]+)")
RX_COMMENT = re.compile(r"<!--.*?-->", re.S)
RX_FENCE = re.compile(r"^\s*(```|~~~).*?^\s*\1\s*$", re.S | re.M)
RX_DETAILS = re.compile(r"<details>.*?</details>", re.S | re.I)
RX_INCLUDE = re.compile(r"\[!INCLUDE\s*\[[^\]]*\]\([^)]*\)\]", re.I)
RX_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
RX_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
RX_REFLINK = re.compile(r"\[([^\]]+)\]\[[^\]]*\]")
RX_ALERT = re.compile(r"\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]", re.I)
RX_TAG = re.compile(r"</?[A-Za-z][^>]*>")
RX_BOLD = re.compile(r"(\*\*|__)(.+?)\1")
RX_ITALIC = re.compile(r"(?<![\w*])\*(?!\s)([^*\n]+?)(?<!\s)\*(?![\w*])")
RX_CODE = re.compile(r"`([^`]*)`")
RX_LIST = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
RX_SPACE = re.compile(r"\s+")
ABBREVIATIONS = {"e.g", "i.e", "etc", "vs", "approx", "no", "ex", "fig", "min", "max", "incl", "u.s", "mr", "ms", "dr", "st"}

# Words kept together when a policy name is split into words.
KEEP_WORDS = [
    "IPv4", "IPv6", "OneDrive", "BitLocker", "PowerShell", "SmartScreen", "WiFi", "ActiveX", "DirectX", "AutoPlay",
    "AutoRun", "AutoAdminLogon", "WebView2", "LinkedIn", "YouTube", "OneNote", "SharePoint", "WinRM", "macOS", "iOS",
    "OAuth", "eSIM", "FIDO2", "NTLMv2", "HoloLens", "MSAL", "ClickOnce", "DevTools", "TouchPad", "OOBE", "AppLocker",
]


def unescape_cell(s):
    return s.replace("\\|", "|")


def split_row(line):
    """Splits a Markdown table row into cells, respecting code spans and escaped pipes."""
    line = line.strip()
    if not line.startswith("|"):
        return None
    cells, cur, code, i = [], [], False, 1
    end = len(line) - 1 if line.endswith("|") and len(line) > 1 else len(line)
    while i < end:
        c = line[i]
        if c == "\\" and i + 1 < end and line[i + 1] == "|":
            cur.append("|")
            i += 2
            continue
        if c == "`":
            code = not code
        if c == "|" and not code:
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    cells.append("".join(cur).strip())
    return cells


def table_rows(text):
    """Returns the body rows of every Markdown table in text, without header and separator rows."""
    rows, header_seen = [], False
    for line in text.splitlines():
        cells = split_row(line)
        if cells is None:
            header_seen = False
            continue
        if not header_seen:
            header_seen = True
            continue
        if all(re.fullmatch(r":?-{2,}:?", c or "") for c in cells):
            continue
        rows.append(cells)
    return rows


def plain(md):
    """Converts a Markdown fragment to plain-text paragraphs. Blockquotes (notes) are returned separately."""
    md = RX_COMMENT.sub("", md)
    md = RX_DETAILS.sub("", md)
    md = RX_FENCE.sub("", md)
    md = RX_INCLUDE.sub("", md)
    paragraphs, quotes, cur, curq = [], [], [], []

    def flush():
        if cur:
            paragraphs.append(" ".join(cur))
            cur[:] = []
        if curq:
            quotes.append(" ".join(curq))
            curq[:] = []

    for raw in md.splitlines():
        line = raw.strip()
        if not line or line.startswith("|") or line.startswith("#"):
            flush()
            continue
        if line.startswith(">"):
            if cur:
                flush()
            text = RX_ALERT.sub("", line.lstrip(">").strip())
            if text:
                curq.append(text)
            continue
        if curq:
            flush()
        if RX_LIST.match(line):
            flush()
            line = RX_LIST.sub("", line)
        cur.append(line)
    flush()
    return [inline(p) for p in paragraphs if inline(p)], [inline(q) for q in quotes if inline(q)]


def inline(s):
    s = RX_IMAGE.sub("", s)
    s = RX_LINK.sub(r"\1", s)
    s = RX_REFLINK.sub(r"\1", s)
    s = re.sub(r"<br\s*/?>", " ", s, flags=re.I)
    s = RX_TAG.sub("", s)
    s = RX_CODE.sub(r"\1", s)
    s = RX_BOLD.sub(r"\2", s)
    s = RX_ITALIC.sub(r"\1", s)
    s = html.unescape(s)
    s = s.replace("\u200b", "").replace("\u00a0", " ")
    return RX_SPACE.sub(" ", s).strip()


def sentences(paragraph):
    """Splits a paragraph into sentences without breaking on common abbreviations."""
    out, start = [], 0
    for m in re.finditer(r"[.!?](?=\s+[\"'(\[]?[A-Z0-9])", paragraph):
        word = paragraph[start:m.start()].rsplit(" ", 1)[-1].lower().strip("(\"'")
        if word in ABBREVIATIONS or re.fullmatch(r"[a-z]", word):
            continue
        out.append(paragraph[start:m.end()].strip())
        start = m.end()
    tail = paragraph[start:].strip()
    if tail:
        out.append(tail)
    return out


def clip(s, limit):
    if len(s) <= limit:
        return s
    cut = s[:limit - 1]
    if " " in cut:
        cut = cut[:cut.rfind(" ")]
    return cut.rstrip(" ,;:-") + "\u2026"


def summary(md, count=2, limit=MAX_DESCRIPTION):
    """The first one or two sentences of a Markdown description, as plain text."""
    paragraphs, quotes = plain(md)
    if not paragraphs:
        paragraphs = quotes
    picked = []
    for p in paragraphs:
        for s in sentences(p):
            if len(s.split()) < 2:
                continue
            picked.append(s)
            if len(picked) >= count:
                break
        if len(picked) >= count:
            break
    if len(picked) > 1 and picked[-1].endswith(":"):
        picked.pop()
    text = " ".join(picked)
    return clip(text, limit)


def meaning(md):
    """A short meaning for an allowed value: the whole text when short, otherwise its first sentence."""
    paragraphs, quotes = plain(md)
    text = " ".join(paragraphs or quotes)
    if len(text) <= SHORT_MEANING:
        return text
    first = sentences(text)
    return clip(first[0] if first else text, MAX_MEANING)


def clean_title(name):
    """A readable title from a policy name: AllowAutoUpdate -> Allow Auto Update, DODownloadMode -> DO Download Mode."""
    s = re.sub(r"^(POL|Pol|L)_", "", name)
    kept = {}
    for i, w in enumerate(KEEP_WORDS):
        token = "\x00%d\x00" % i
        if w in s:
            s = s.replace(w, " " + token + " ")
            kept[token] = w
    words = []
    for part in re.split(r"[_\s]+", s):
        if not part:
            continue
        if part in kept:
            words.append(kept[part])
            continue
        words.extend(re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+|[^A-Za-z\d]+", part))
    return RX_SPACE.sub(" ", " ".join(words)).strip()


def strip_title(desc, titles):
    """Drops a leading copy of the policy title, as in 'Network security: Restrict NTLM: ... This policy setting ...'."""
    for t in titles:
        if t and len(desc) > len(t) + 20 and desc.lower().startswith(t.lower()):
            rest = desc[len(t):].lstrip(" .:-")
            if rest[:1].isupper():
                return rest
    return desc


def escape(s):
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


class Policy(object):
    def __init__(self, area, name, source):
        self.area = area
        self.name = name
        self.source = source
        self.device = False
        self.user = False
        self.friendly = ""
        self.friendly_from = "title"
        self.description = ""
        self.format = ""
        self.default = ""
        self.range = ""
        self.values = collections.OrderedDict()
        self.admx_backed = False
        self.admx_file = ""
        self.admx_policy = ""
        self.gp_path = ""
        self.gp_location = ""
        self.gp_element = ""
        self.gp_key = ""
        self.gp_value = ""
        self.has_mapping = False
        self.has_values_section = False
        self.missing = []

    @property
    def scope(self):
        if self.device and self.user:
            return "Both"
        return "Device" if self.device else "User" if self.user else ""

    def row(self):
        values = "\n".join(k + "\t" + v for k, v in self.values.items())
        return [self.area, self.name, self.scope, self.friendly, self.description, self.format, self.default, self.range, values,
                "1" if self.admx_backed else "", self.admx_file, self.admx_policy, self.gp_path, self.gp_location,
                self.gp_element, self.gp_key, self.gp_value]


def is_security_path(path):
    return path.startswith("Windows Settings > Security Settings")


def apply_mapping(p, body):
    """Reads a 'Group policy mapping' or 'ADMX mapping' table."""
    fields = {}
    for cells in table_rows(body):
        if len(cells) >= 2 and cells[0] and cells[0] not in fields:
            fields[cells[0].lower()] = inline(cells[1])
    if not fields:
        return
    p.has_mapping = True
    p.admx_policy = fields.get("name", "")
    p.gp_path = fields.get("path", "")
    p.gp_location = fields.get("location", "")
    p.gp_element = fields.get("element name", "")
    p.gp_key = fields.get("registry key name", "").strip().strip("\\")
    p.gp_value = fields.get("registry value name", "")
    p.admx_file = fields.get("admx file name", "")
    friendly = fields.get("friendly name", "")
    if friendly:
        p.friendly, p.friendly_from = friendly, "gp"
    elif is_security_path(p.gp_path) and p.admx_policy:
        p.friendly, p.friendly_from = p.admx_policy, "gp"
    if is_security_path(p.gp_path):
        p.admx_policy = ""


def apply_dfproperties(p, body):
    for cells in table_rows(body):
        if len(cells) < 2:
            continue
        key, value = cells[0].lower(), cells[1]
        if key == "format":
            m = re.search(r"`([^`]+)`", value)
            p.format = (m.group(1) if m else value).strip()
        elif key == "default value":
            p.default = inline(value)
        elif key == "allowed values":
            m = re.search(r"Range:\s*`\[([^\]]+)\]`", value)
            if m:
                p.range = m.group(1).strip()


def apply_allowed_values(p, body):
    p.has_values_section = True
    for cells in table_rows(body):
        if len(cells) < 2:
            continue
        key = inline(cells[0])
        m = re.match(r"^(.*?)\s*\(Default\)\s*$", key, re.I)
        if m:
            key = m.group(1).strip()
            if not p.default:
                p.default = key
        if not key or key.lower() in ("value", "flag"):
            continue
        p.values[key] = meaning(unescape_cell(cells[1]))


def parse_generated(path, text, stats):
    """Parses an auto-generated Policy CSP file with <!-- Policy-Section-Begin --> markers."""
    sections = collections.defaultdict(dict)
    for m in RX_SECTION.finditer(text):
        sections[m.group(1)].setdefault(m.group(2), m.group(3))
    out = []
    for sid, secs in sections.items():
        oma = secs.get("OmaUri")
        if oma is None:
            continue
        uris = RX_OMA.findall(oma)
        if not uris:
            stats["no-oma-uri"] += 1
            continue
        area, name = uris[0][1], uris[0][2]
        p = Policy(area, name, os.path.basename(path))
        for scope, a, n in uris:
            if (a, n) != (area, name):
                stats["oma-uri-mismatch"] += 1
            if scope == "Device":
                p.device = True
            else:
                p.user = True
        applic = secs.get("Applicability", "")
        if not p.device and not p.user:
            p.device = "\u2705 Device" in applic
            p.user = "\u2705 User" in applic
        desc = secs.get("Description", "")
        p.description = summary(desc)
        if not p.description:
            p.description = summary(secs.get("Editable", ""))
        apply_dfproperties(p, secs.get("DFProperties", ""))
        if "AllowedValues" in secs:
            apply_allowed_values(p, secs["AllowedValues"])
        if "AdmxBacked" in secs:
            p.admx_backed = True
            apply_mapping(p, secs["AdmxBacked"])
        if "GpMapping" in secs and not p.gp_key:
            apply_mapping(p, secs["GpMapping"])
        out.append(p)
    return out


def parse_legacy(path, text, stats):
    """Parses the older hand-written format: <!--Policy--> blocks with **Area/Name** headings and 'ADMX Info' lists."""
    out = []
    for block in re.findall(r"<!--Policy-->(.*?)<!--/Policy-->", text, re.S):
        m = re.search(r"\*\*([A-Za-z0-9_~.-]+)/([A-Za-z0-9_~.-]+)\*\*", block)
        if not m:
            stats["legacy-without-name"] += 1
            continue
        p = Policy(m.group(1), m.group(2), os.path.basename(path))
        scope = re.search(r"<!--Scope-->(.*?)<!--/Scope-->", block, re.S)
        if scope:
            p.device = re.search(r"\*\s+Machine", scope.group(1)) is not None
            p.user = re.search(r"\*\s+User", scope.group(1)) is not None
        desc = re.search(r"<!--Description-->(.*?)<!--/Description-->", block, re.S)
        if desc:
            body = desc.group(1)
            for v in re.finditer(r"^\s*[-*]\s+(\d+)\s*[-\u2013:]\s*(?:(Default)\s*[-\u2013:]\s*)?(.+)$", body, re.M):
                p.values[v.group(1)] = meaning(v.group(3))
                if v.group(2) and not p.default:
                    p.default = v.group(1)
            if p.values:
                p.has_values_section = True
            body = re.sub(r"^\s*[-*]\s+\d+\s*[-\u2013:].*$", "", body, flags=re.M)
            p.description = summary(body)
        admx = re.search(r"<!--ADMXBacked-->(.*?)<!--/ADMXBacked-->", block, re.S)
        if admx:
            info = {}
            for line in admx.group(1).splitlines():
                lm = re.match(r"^\s*[-*]\s+GP ([^:]+):\s*(.+)$", line)
                if lm:
                    info[lm.group(1).strip().lower()] = inline(lm.group(2)).strip("*_ ")
            if info:
                p.has_mapping = True
                p.admx_backed = True
                p.admx_policy = info.get("name", "")
                p.gp_path = info.get("path", "").replace("\\", " > ")
                p.admx_file = info.get("admx file name", "")
                p.gp_element = info.get("element", "")
                friendly = info.get("friendly name") or info.get("english name")
                if friendly:
                    p.friendly, p.friendly_from = friendly, "gp"
        stats["legacy-format"] += 1
        out.append(p)
    return out


def check(p):
    """Records which parts of a policy could not be parsed."""
    if not p.scope:
        p.missing.append("scope")
    if not p.description:
        p.missing.append("description")
    if p.has_values_section and not p.values:
        p.missing.append("allowed values")
    if p.has_mapping and not is_security_path(p.gp_path):
        if not p.gp_key:
            p.missing.append("registry key")
        if not p.admx_file:
            p.missing.append("ADMX file")


def git_info(folder):
    def run(*args):
        try:
            return subprocess.check_output(["git", "-C", folder] + list(args), stderr=subprocess.DEVNULL).decode("utf-8").strip()
        except (OSError, subprocess.CalledProcessError):
            return ""
    line = run("log", "-1", "--format=%H %cI")
    commit, date = (line.split(" ", 1) + [""])[:2] if line else ("", "")
    return commit, date[:10], run("remote", "get-url", "origin"), run("rev-parse", "--abbrev-ref", "HEAD")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Build the PolicyVice Policy CSP catalog from Microsoft's Policy CSP documentation.")
    ap.add_argument("docs", help="checkout of the Windows client documentation, or its windows/client-management/mdm folder")
    ap.add_argument("-o", "--output", default=os.path.join(here, "..", "res", "PolicyCsp.tsv.gz"), help="output file (default: res/PolicyCsp.tsv.gz)")
    ap.add_argument("--commit", help="docs commit, when the input is not a git checkout")
    ap.add_argument("--date", help="docs commit date (yyyy-mm-dd), when the input is not a git checkout")
    ap.add_argument("--source", help="repository the docs were fetched from (default: the checkout's origin)")
    ap.add_argument("--upstream", default=UPSTREAM, help="canonical documentation repository (default: %(default)s)")
    ap.add_argument("--tsv", help="also write the uncompressed TSV here, for review")
    args = ap.parse_args()

    folder = args.docs
    mdm = os.path.join(folder, "windows", "client-management", "mdm")
    if os.path.isdir(mdm):
        folder_root, folder = folder, mdm
    else:
        folder_root = folder
    files = sorted(glob.glob(os.path.join(folder, "policy-csp-*.md")))
    if not files:
        sys.exit("No policy-csp-*.md files in " + folder)

    commit, date, origin, branch = git_info(folder_root)
    commit = args.commit or commit
    date = args.date or date
    source = args.source or re.sub(r"\.git$", "", origin)
    if not commit:
        sys.exit("The docs commit is not known. Pass --commit and --date.")

    stats = collections.Counter()
    policies = {}
    for path in files:
        with io.open(path, encoding="utf-8-sig") as f:
            text = f.read().replace("\r\n", "\n")
        found = parse_generated(path, text, stats)
        if not found and "<!--Policy-->" in text:
            found = parse_legacy(path, text, stats)
        if not found:
            stats["files-without-policies"] += 1
            print("warning: no policies in " + os.path.basename(path), file=sys.stderr)
        stats["files"] += 1
        for p in found:
            key = (p.area.lower(), p.name.lower())
            if key in policies:
                stats["duplicates"] += 1
                print("warning: %s/%s is in %s and %s, keeping the first" % (p.area, p.name, policies[key].source, p.source), file=sys.stderr)
                continue
            policies[key] = p

    for p in policies.values():
        if not p.friendly:
            p.friendly = clean_title(p.name)
        p.description = strip_title(p.description, [p.friendly, p.admx_policy])
        check(p)

    rows = [policies[k] for k in sorted(policies)]
    full = [p for p in rows if not p.missing]
    missing = collections.Counter(m for p in rows for m in p.missing)

    buf = io.StringIO()
    meta = [("format", FORMAT), ("upstream", args.upstream), ("source", source), ("branch", branch), ("commit", commit),
            ("date", date), ("license", LICENSE), ("entries", str(len(rows)))]
    for k, v in meta:
        if v:
            buf.write("#" + k + "\t" + escape(v) + "\n")
    buf.write("\t".join(COLUMNS) + "\n")
    for p in rows:
        buf.write("\t".join(escape(c) for c in p.row()) + "\n")
    data = buf.getvalue().encode("utf-8")

    out = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as gz:
            gz.write(data)
    if args.tsv:
        with open(args.tsv, "wb") as f:
            f.write(data)

    def count(pred):
        return sum(1 for p in rows if pred(p))

    print("Source:   %s (%s), commit %s, %s" % (source or args.upstream, branch or "?", commit, date or "?"))
    print("Files:    %d policy-csp-*.md files, %d in the legacy format" % (stats["files"], 1 if stats["legacy-format"] else 0))
    print("Policies: %d (%d full, %d partial)" % (len(rows), len(full), len(rows) - len(full)))
    for k, v in sorted(missing.items(), key=lambda kv: -kv[1]):
        print("  missing %-15s %d" % (k, v))
    print("Scope:    %d Device, %d User, %d both" % (count(lambda p: p.scope == "Device"), count(lambda p: p.scope == "User"), count(lambda p: p.scope == "Both")))
    print("Areas:    %d (%d ADMX_ areas)" % (len({p.area.lower() for p in rows}), len({p.area.lower() for p in rows if p.area.lower().startswith("admx_")})))
    print("Mapping:  %d with a Group Policy mapping, %d ADMX-backed, %d with an ADMX file, %d with a registry key, %d with a value name"
          % (count(lambda p: p.has_mapping), count(lambda p: p.admx_backed), count(lambda p: p.admx_file), count(lambda p: p.gp_key), count(lambda p: p.gp_value)))
    print("Names:    %d from Group Policy, %d from the policy name" % (count(lambda p: p.friendly_from == "gp"), count(lambda p: p.friendly_from == "title")))
    print("Values:   %d with allowed values (%d values), %d with a default, %d with a range"
          % (count(lambda p: p.values), sum(len(p.values) for p in rows), count(lambda p: p.default), count(lambda p: p.range)))
    for k in ("duplicates", "no-oma-uri", "oma-uri-mismatch", "files-without-policies"):
        if stats[k]:
            print("Warning:  %s %d" % (k, stats[k]))
    print("Output:   %s, %d bytes (%d uncompressed)" % (os.path.relpath(out), os.path.getsize(out), len(data)))


if __name__ == "__main__":
    main()
