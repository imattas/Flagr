"""
Directory/File Brute Force

This unit will attempt to discover hidden files and directories on a web
server by requesting a list of commonly used paths and checking for
HTTP 200 responses.

This unit inherits from :class:`flagr.units.web.WebUnit` as that contains
lots of predefined variables that can be used throughout multiple web units.

.. warning::

    This unit automatically attempts to perform malicious actions on the
    target. **DO NOT** use this in any circumstances where you do not have the
    authority to operate!

"""

import requests

from flagr.unit import NotApplicable
from flagr.units.web import WebUnit


COMMON_PATHS = [
    "/flag",
    "/flag.txt",
    "/admin",
    "/robots.txt",
    "/backup",
    "/.env",
    "/config",
    "/debug",
    "/console",
    "/api",
    "/api/flag",
    "/secret",
    "/.git/HEAD",
    "/.svn/entries",
    "/wp-admin",
    "/sitemap.xml",
    "/server-status",
    "/.DS_Store",
    "/backup.zip",
    "/dump.sql",
    "/.htaccess",
    "/phpinfo.php",
    "/shell.php",
    "/cmd.php",
]
"""
A list of common paths to brute-force on the target web server.
"""


class Unit(WebUnit):

    GROUPS = ["web", "recon", "dirbuster"]
    """
    These are "tags" for a unit. Considering it is a Web unit, "web"
    is included, as well as the name of the unit, "dirbuster".
    """

    RECURSE_SELF = False
    """
    This unit should not recurse into itself.
    """

    PRIORITY = 30
    """
    Priority works with 0 being the highest priority, and 100 being the
    lowest priority. 50 is the default priority. This unit has a somewhat
    higher priority.
    """

    def __init__(self, *args, **kwargs):
        """
        The constructor is included to first determine if the target URL
        is reachable. If the target cannot be reached, this unit will abort.
        """

        super(Unit, self).__init__(*args, **kwargs)

        url = self.target.upstream.decode("utf-8", errors="replace")

        try:
            r = requests.get(url, timeout=10)
        except requests.exceptions.ConnectionError:
            raise NotApplicable("cannot reach url")
        except requests.exceptions.Timeout:
            raise NotApplicable("request timed out")

        self.base_url = self.target.url_root.rstrip("/")

    def enumerate(self):
        """
        Yield each common path to be tested against the target.

        :return: A generator, yielding path strings.
        """

        for path in COMMON_PATHS:
            yield path

    def evaluate(self, case):
        """
        Evaluate the target. Request each common path and register any
        that return an HTTP 200 response.

        :param case: A path string returned by ``enumerate``.

        :return: None. This function should not return any data.
        """

        path = case
        url = "{0}{1}".format(self.base_url, path)

        try:
            r = requests.get(url, timeout=10, allow_redirects=True)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return

        if r.status_code == 200:
            self.manager.register_data(
                self, "Found: {} [200]".format(url), recurse=False
            )

            # Register the response content for further analysis
            self.manager.register_data(self, r.text)

            # Also look for flags in the response
            self.manager.find_flag(self, r.text)
