"""Technology fingerprinting from headers, cookies, meta tags, markup and asset URLs."""
import re


SIGNATURES = [
    ("nginx", "web-server", "nginx:nginx", [("header:server", r"nginx(?:/([\d.]+))?")]),
    ("Apache HTTP Server", "web-server", "apache:http_server", [("header:server", r"apache(?!-coyote)(?:/([\d.]+))?")]),
    ("Microsoft IIS", "web-server", "microsoft:internet_information_services", [("header:server", r"microsoft-iis/([\d.]+)")]),
    ("LiteSpeed", "web-server", None, [("header:server", r"litespeed")]),
    ("OpenResty", "web-server", None, [("header:server", r"openresty(?:/([\d.]+))?")]),
    ("Caddy", "web-server", None, [("header:server", r"caddy")]),
    ("Cloudflare", "cdn/waf", None, [("header:cf-ray", r"."), ("header:server", r"cloudflare")]),
    ("Amazon CloudFront", "cdn", None, [("header:x-amz-cf-id", r"."), ("header:via", r"cloudfront")]),
    ("Fastly", "cdn", None, [("header:x-fastly-request-id", r".")]),
    ("Akamai", "cdn/waf", None, [("header:server", r"akamaighost"), ("header:x-akamai-transformed", r".")]),
    ("Varnish", "cache", None, [("header:x-varnish", r"."), ("header:via", r"varnish")]),
    ("Vercel", "hosting", None, [("header:server", r"vercel"), ("header:x-vercel-id", r".")]),
    ("Netlify", "hosting", None, [("header:server", r"netlify")]),
    ("PHP", "language", "php:php", [("header:x-powered-by", r"php(?:/([\d.]+))?")]),
    ("ASP.NET", "framework", None, [("header:x-aspnet-version", r"([\d.]+)"), ("header:x-powered-by", r"asp\.net")]),
    ("Express", "framework", None, [("header:x-powered-by", r"express")]),
    ("WordPress", "cms", "wordpress:wordpress", [("meta", r"wordpress ([\d.]+)"), ("html", r"/wp-(?:content|includes)/")]),
    ("Drupal", "cms", "drupal:drupal", [("meta", r"drupal (\d+)"), ("header:x-generator", r"drupal (\d+)"), ("html", r"drupal-settings-json")]),
    ("Joomla", "cms", None, [("meta", r"joomla")]),
    ("Shopify", "ecommerce", None, [("html", r"cdn\.shopify\.com"), ("header:x-shopid", r".")]),
    ("Wix", "builder", None, [("html", r"static\.wixstatic\.com")]),
    ("Squarespace", "builder", None, [("html", r"squarespace")]),
    ("Laravel", "framework", None, [("cookie", r"laravel_session")]),
    ("Django", "framework", None, [("cookie", r"csrftoken")]),
    ("Ruby on Rails", "framework", None, [("html", r"name=[\"']csrf-param[\"']")]),
    ("React", "js-framework", None, [("html", r"data-reactroot"), ("asset", r"react(?:-dom)?(?:@|[.-])([\d.]+)?(?:\.production)?(?:\.min)?\.js")]),
    ("Next.js", "js-framework", None, [("html", r"__next_data__|/_next/static/")]),
    ("Nuxt", "js-framework", None, [("html", r"__nuxt|/_nuxt/")]),
    ("Vue.js", "js-framework", None, [("asset", r"vue(?:\.runtime)?(?:@|[.-])?([\d.]+)?(?:\.min)?\.js"), ("html", r"data-v-[0-9a-f]{8}")]),
    ("Angular", "js-framework", "angular:angular", [("html", r"ng-version=\"([\d.]+)\"")]),
    ("jQuery", "js-library", "jquery:jquery", [("asset", r"jquery[/@-]v?(\d+\.\d+(?:\.\d+)?)"), ("asset", r"jquery(?:[.-]v?(\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.js")]),
    ("Bootstrap", "ui-framework", "getbootstrap:bootstrap", [("asset", r"bootstrap[/@-]v?(\d+\.\d+(?:\.\d+)?)"), ("asset", r"bootstrap(?:[.-]v?(\d+\.\d+(?:\.\d+)?))?(?:\.bundle)?(?:\.min)?\.(?:css|js)")]),
    ("Google Tag Manager", "analytics", None, [("html", r"googletagmanager\.com")]),
    ("Google Analytics", "analytics", None, [("html", r"google-analytics\.com|gtag/js")]),
    ("reCAPTCHA", "security", None, [("html", r"google\.com/recaptcha")]),
]


def _meta_generators(html):
    found = re.findall(r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)", html, re.I)
    found += re.findall(r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]*name=[\"']generator[\"']", html, re.I)
    return found


def detect(headers, cookies, html):
    h = {k.lower(): v for k, v in headers.items()}
    html = (html or "")[:500_000]
    metas = _meta_generators(html)
    assets = re.findall(r"(?:src|href)=[\"']([^\"']+)", html, re.I)
    cookie_names = " ".join(c.split("=")[0] for c in cookies)

    results = []
    for name, category, cpe, checks in SIGNATURES:
        version, evidence = None, None
        for source, pattern in checks:
            rx = re.compile(pattern, re.I)
            candidates = []
            if source.startswith("header:"):
                value = h.get(source.split(":", 1)[1])
                candidates = [f"{source.split(':', 1)[1]}: {value}"] if value else []
                match = rx.search(value) if value else None
            elif source == "cookie":
                match = rx.search(cookie_names)
                candidates = [f"cookie: {match.group(0)}"] if match else []
            elif source == "meta":
                match = next((m for m in (rx.search(x) for x in metas) if m), None)
                candidates = [f"meta generator: {match.group(0)}"] if match else []
            elif source == "html":
                match = rx.search(html)
                candidates = ["markup signature"] if match else []
            else:  # asset
                match = next((m for m in (rx.search(a) for a in assets) if m), None)
                candidates = [f"asset: {match.group(0)}"] if match else []
            if match:
                evidence = candidates[0] if candidates else source
                if match.groups() and match.group(1) and not version:
                    version = match.group(1).rstrip(".")
                if version:
                    break
        if evidence:
            entry = {"name": name, "category": category, "version": version, "evidence": evidence, "cpe": None}
            if version and cpe:
                entry["cpe"] = f"cpe:2.3:a:{cpe}:{version}"
            results.append(entry)
    return results
