import tornado.ioloop
import tornado.web
import base64
import lxml.etree
import crypto
import io

def log_message_details(request):
    print(request.headers)
    print(request.body)

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Hello, world")

class Sign(tornado.web.RequestHandler):
    private_key = crypto.load_private_key()

    def post(self):
        log_message_details(self.request)
        signature = crypto.sign_message(self.request.body, self.private_key)
        signature = base64.urlsafe_b64encode(signature)
        self.add_header("signature", signature)
        self.write(self.request.body)

class Verify(tornado.web.RequestHandler):
    #public_key = crypto.load_public_key()
    public_key = crypto.load_public_key_from_cert()

    def post(self):
        log_message_details(self.request)
        signature = self.request.headers['signature']
        signature = base64.urlsafe_b64decode(signature)
        crypto.verify_message(self.request.body, signature, self.public_key)
        self.write("Signature verified successfully")

class Canonicalize(tornado.web.RequestHandler):
    def post(self):
        xml_tree = lxml.etree.fromstring(self.request.body)
        canonical_xml = lxml.etree.tostring(xml_tree, method='c14n', exclusive=True, with_comments=False)
        self.write(canonical_xml)

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/sign", Sign),
        (r"/verify", Verify),
        (r"/canonicalize", Canonicalize)
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
