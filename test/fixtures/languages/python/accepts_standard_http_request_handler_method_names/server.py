class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        return self.send_response(200)

def buildResponse():
    return "invalid"
