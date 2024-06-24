from flask import Flask, render_template
from gevent.pywsgi import WSGIServer

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/projects')
def projects():
    return render_template('projects.html')


if __name__ == '__main__':
    # listener = Listener(app)
    http_server = WSGIServer(('0.0.0.0', 80), app)
    http_server.serve_forever()
