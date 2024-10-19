from sphinx.application import Sphinx

def setup(app: Sphinx):
    app.config.linkcheck_workers = 1
    app.config.linkcheck_ignore = [
        'https://github.com',
        'http://github.com',
    ]
    app.config.linkcheck_request_headers = {
        "*": {
            "Accept": "text/html,application/atom+xml",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0",
        }
    }
