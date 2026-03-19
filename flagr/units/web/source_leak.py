"""
Source Code Leak Detection

This unit will check for common source code leaks on a web server, including
exposed Git repositories, SVN metadata, environment files, backup archives,
and other sensitive files that may have been left accessible.

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


LEAK_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.env",
    "/backup.zip",
    "/backup.tar.gz",
    "/source.zip",
    "/index.php.bak",
    "/index.php~",
    "/config.php.bak",
    "/config.php~",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/.htpasswd",
    "/.htpasswd.bak",
    "/web.config.bak",
    "/app.py.bak",
    "/app.py~",
    "/main.py.bak",
    "/main.py~",
]
"""
A list of common source code leak paths to check on the target web server.
"""

GIT_OBJECT_PATTERN = r"[0-9a-f]{40}"
"""
Pattern to match Git object SHA1 hashes.
"""


class Unit(WebUnit):

    GROUPS = ["web", "recon", "source_leak"]
    """
    These are "tags" for a unit. Considering it is a Web unit, "web"
    is included, as well as the name of the unit, "source_leak".
    """

    RECURSE_SELF = False
    """
    This unit should not recurse into itself.
    """

    PRIORITY = 25
    """
    Priority works with 0 being the highest priority, and 100 being the
    lowest priority. 50 is the default priority. This unit has a higher
    priority.
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
        Yield each leak path to be tested against the target.

        :return: A generator, yielding path strings.
        """

        for path in LEAK_PATHS:
            yield path

    def evaluate(self, case):
        """
        Evaluate the target. Request each source leak path and register
        any content found. If a .git/HEAD file is found, attempt to fetch
        Git objects referenced within it.

        :param case: A path string returned by ``enumerate``.

        :return: None. This function should not return any data.
        """

        import re

        path = case
        url = "{0}{1}".format(self.base_url, path)

        try:
            r = requests.get(url, timeout=10, allow_redirects=False)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return

        if r.status_code != 200:
            return

        self.manager.register_data(
            self, "Source leak found: {} [200]".format(url), recurse=False
        )

        # Register the content for further analysis
        self.manager.register_data(self, r.text)

        # Look for flags in the response
        self.manager.find_flag(self, r.text)

        # If this is .git/HEAD, try to fetch referenced objects
        if path == "/.git/HEAD" and r.text.startswith("ref:"):
            ref_path = r.text.strip().split("ref: ", 1)[-1]
            self._fetch_git_ref(ref_path)

        # If this is .git/config, register the content
        if path == "/.git/config":
            self.manager.register_data(
                self, "Git config: {}".format(r.text), recurse=False
            )

    def _fetch_git_ref(self, ref_path):
        """
        Attempt to fetch a Git reference and its associated objects.

        :param ref_path: The ref path from .git/HEAD (e.g. refs/heads/master).
        """

        import re

        # Try to get the ref file
        ref_url = "{0}/.git/{1}".format(self.base_url, ref_path)

        try:
            r = requests.get(ref_url, timeout=10, allow_redirects=False)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return

        if r.status_code != 200:
            return

        commit_hash = r.text.strip()

        self.manager.register_data(
            self,
            "Git ref {}: {}".format(ref_path, commit_hash),
            recurse=False,
        )

        # Try to fetch the commit object
        if re.match(GIT_OBJECT_PATTERN, commit_hash):
            self._fetch_git_object(commit_hash)

    def _fetch_git_object(self, obj_hash):
        """
        Attempt to fetch a Git object by its SHA1 hash.

        :param obj_hash: The SHA1 hash of the Git object.
        """

        obj_url = "{0}/.git/objects/{1}/{2}".format(
            self.base_url, obj_hash[:2], obj_hash[2:]
        )

        try:
            r = requests.get(obj_url, timeout=10, allow_redirects=False)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return

        if r.status_code == 200:
            self.manager.register_data(
                self,
                "Git object found: {}".format(obj_hash),
                recurse=False,
            )

            # Try to decompress and register the object content
            try:
                import zlib

                decompressed = zlib.decompress(r.content)
                self.manager.register_data(self, decompressed.decode("utf-8", errors="replace"))
                self.manager.find_flag(
                    self, decompressed.decode("utf-8", errors="replace")
                )
            except Exception:
                pass
