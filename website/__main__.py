from flask import Flask, render_template
from gevent.pywsgi import WSGIServer

from flask_recon import Listener, add_routes

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/projects')
def projects():
    return render_template('projects.html')


@app.route('/also-see')
def also_see():
    return render_template('check-out.html')


@app.route('/about-me')
def about_me():
    return render_template('about.html')


@app.route('/sitemap.xml')
def sitemap():
    return open("sitemap.xml", "rb").read()


if __name__ == '__main__':
    listener = Listener(app, halt_scanner_threads=False)
    add_routes(listener, run_api=False, run_webapp=True)
    listener.connect_database("new_flask_recon", "postgres", "postgres", "localhost", "5432")
    http_server = WSGIServer(('0.0.0.0', 443), listener, keyfile="key.pem", certfile="cert.pem")
    http_server.serve_forever()
