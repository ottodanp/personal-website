from flask import Flask, render_template, request, Response
from gevent.pywsgi import WSGIServer

from flask_recon import Listener, add_routes
import ip_address_checker
from ip_address_checker.database import IpNotFound

app = Flask(__name__)
ip_address_db_handler = ip_address_checker.DatabaseHandler("new_flask_recon", "postgres", "postgres", "localhost", "5432")


@app.route('/')
def index():
    args = request.args
    if args.get("source"):
        source = args.get("source")
        with open("sources.txt", "a") as sources_file:
            sources_file.write(f"{source}\n")

    return render_template('index.html')


@app.route('/projects/flask-recon')
def flask_recon_summary():
    return render_template('project-summaries/flask-recon.html')


@app.route('/projects/this-website')
def this_website_summary():
    return render_template('project-summaries/this-website.html')


@app.route('/projects/network-monitor')
def network_monitor_summary():
    return render_template('project-summaries/network-monitor.html')


@app.route('/also-see')
def also_see():
    return render_template('check-out.html')


@app.route('/about-me')
def about_me():
    return render_template('about.html')


@app.route('/ip-lookup', methods=["GET", "POST"])
def ip_lookup():
    if request.method == "GET":
        return render_template('ip-address-search.html')

    elif request.method == "POST":
        ip_address = request.form["ip_address"]
        try:
            host_id, host, request_count = ip_address_db_handler.get_ip_details(ip_address)
        except IpNotFound:
            return render_template('ip-address-search-result.html', host_id=None, host=None, request_count=None)
        return render_template('ip-address-search-result.html', host_id=host_id, host=host, request_count=request_count)


@app.route('/sitemap.xml')
def sitemap():
    return open("sitemap.xml", "rb").read()


@app.route("/cv")
def cv():
    response = Response(open("cv.pdf", "rb").read())
    response.headers["Content-Type"] = "application/pdf"
    return response


if __name__ == '__main__':
    listener = Listener(app, halt_scanner_threads=False)
    add_routes(listener, run_api=False, run_webapp=True)
    listener.connect_database("new_flask_recon", "postgres", "postgres", "localhost", "5432")
    http_server = WSGIServer(('0.0.0.0', 443), listener, keyfile="key.pem", certfile="cert.pem")
    http_server.serve_forever()
