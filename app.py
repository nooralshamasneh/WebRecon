"""WebRecon - web interface.

Run:  python app.py
Env:  WEBRECON_HOST (default 127.0.0.1), WEBRECON_PORT (default 8080),
      WEBRECON_DEBUG=1 (never use on a public network),
      WEBRECON_MAX_CONCURRENT (default 2), WEBRECON_ALLOW_PRIVATE=1 (lab use only)
"""
import os
import re
import threading
import uuid
from collections import OrderedDict

from flask import Flask, abort, jsonify, render_template, request, send_file

import webrecon_backend as backend

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

MAX_STORED_SCANS = 20

app = Flask(__name__)

_scans = OrderedDict()  # scan_id -> results (kept in memory, newest last)
_lock = threading.Lock()
_slots = threading.BoundedSemaphore(int(os.environ.get("WEBRECON_MAX_CONCURRENT", "2")))


def _report_path(scan_id):
    return os.path.join(REPORT_DIR, f"{scan_id}.pdf")


def _store(scan_id, results):
    with _lock:
        _scans[scan_id] = results
        while len(_scans) > MAX_STORED_SCANS:
            old_id, _ = _scans.popitem(last=False)
            try:
                os.remove(_report_path(old_id))
            except OSError:
                pass


def _get(scan_id):
    with _lock:
        return _scans.get(scan_id)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html", results=None, target="", error=None)

    target = request.form.get("target", "").strip()

    if request.form.get("consent") != "on":
        return render_template("index.html", results=None, target=target,
                               error="Confirm that you are authorized to scan this target."), 400

    if not _slots.acquire(blocking=False):
        return render_template("index.html", results=None, target=target,
                               error="The server is busy with other scans. Try again in a minute."), 429
    try:
        scan_id = uuid.uuid4().hex
        results = backend.scan_target(target, scan_id, _report_path(scan_id))
        _store(scan_id, results)
        return render_template("index.html", results=results, target=target, error=None)
    except backend.InvalidTarget as exc:
        return render_template("index.html", results=None, target=target, error=str(exc)), 400
    except Exception:
        app.logger.exception("Scan failed")
        return render_template("index.html", results=None, target=target,
                               error="The scan failed unexpectedly. Check the server log."), 500
    finally:
        _slots.release()


def _safe_name(results):
    return re.sub(r"[^A-Za-z0-9._-]", "_", results["target"])


@app.get("/export/<scan_id>/pdf")
def export_pdf(scan_id):
    results = _get(scan_id)
    path = _report_path(scan_id)
    if not results or not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True,
                     download_name=f"WebRecon_{_safe_name(results)}.pdf")


@app.get("/export/<scan_id>/json")
def export_json(scan_id):
    results = _get(scan_id)
    if not results:
        abort(404)
    resp = jsonify(results)
    resp.headers["Content-Disposition"] = f'attachment; filename="WebRecon_{_safe_name(results)}.json"'
    return resp


if __name__ == "__main__":
    host = os.environ.get("WEBRECON_HOST", "127.0.0.1")
    port = int(os.environ.get("WEBRECON_PORT", "8080"))
    debug = os.environ.get("WEBRECON_DEBUG") == "1"
    print(f"Starting WebRecon on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)