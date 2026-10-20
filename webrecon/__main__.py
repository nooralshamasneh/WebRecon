import sys

from . import create_app

app = create_app()
cfg = app.extensions["webrecon"].cfg
if cfg["HOST"] not in ("127.0.0.1", "localhost", "::1"):
    print("WARNING: binding to a non-loopback address. Put WebRecon behind HTTPS and set WEBRECON_HTTPS=1.", file=sys.stderr)
print(f"WebRecon on http://{cfg['HOST']}:{cfg['PORT']}")
app.run(host=cfg["HOST"], port=cfg["PORT"], debug=False)
