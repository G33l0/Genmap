from genmap.nmap.nse_docs import load_script_documentation, parse_script_documentation

LONG = '''local http = require "http"

description = [[
Shows the title of the default page of a web server.

The script will follow up to 5 HTTP redirects, using the default rules in the
http library.
]]

---
--@args http-title.url The url to fetch. Default: /
--@output
-- Nmap scan report for scanme.nmap.org (74.207.244.221)
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-title: Go ahead and ScanMe!
--
-- @see http-headers.nse
-- @usage
-- nmap --script http-title -p80 <target>

author = {"Diman Todorov", "Brendan Coles"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.http

-- @args not.real This comment is after the header and must be ignored.
'''

SHORT = '''description = "Checks for \\"quoted\\" things on a service."
---
-- @args demo.timeout time to wait
--       for a reply (default: 10s)
-- @args demo.flag
author = "Someone"
categories = {"safe"}
'''


def test_long_description_and_tags():
    doc = parse_script_documentation("http-title", LONG)
    assert doc.summary == "Shows the title of the default page of a web server."
    assert "5 HTTP redirects" in doc.description
    assert [(a.name, a.description) for a in doc.arguments] == [("http-title.url", "The url to fetch. Default: /")]
    assert doc.output.splitlines()[-1] == "|_http-title: Go ahead and ScanMe!"
    assert doc.usage == ["nmap --script http-title -p80 <target>"]
    assert doc.see_also == ["http-headers.nse"]
    assert doc.authors == ["Diman Todorov", "Brendan Coles"]


def test_short_description_and_multiline_arguments():
    doc = parse_script_documentation("demo", SHORT)
    assert doc.description == 'Checks for "quoted" things on a service.'
    assert [(a.name, a.description) for a in doc.arguments] == [
        ("demo.timeout", "time to wait for a reply (default: 10s)"),
        ("demo.flag", ""),
    ]
    assert doc.authors == ["Someone"]


def test_missing_files(tmp_path):
    assert not load_script_documentation(None, "x").readable
    assert not load_script_documentation(tmp_path, "missing").readable
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "demo.nse").write_text(SHORT)
    assert load_script_documentation(tmp_path, "demo").arguments[0].name == "demo.timeout"
