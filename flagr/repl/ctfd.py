#!/usr/bin/env python3
"""
CTFd provider for flagr remote CTF integration.

Supports:
  - Session-based authentication (username/password login via form)
  - API token authentication (set password to "token:<your-api-token>")
  - Challenge listing, details, file URLs, and flag submission
  - Scoreboard with team and user support
  - Solve tracking

Tested with CTFd v2.x and v3.x APIs.
"""
from typing import Generator, Tuple, List, Any, Dict
import requests

from flagr.repl.ctf import CTFProvider, Challenge, User, AuthenticationError, Bracket


class Provider(CTFProvider):
    def __init__(self, *args, **kwargs):
        self.session: requests.Session = None
        self.csrf_token: str = None
        self._challenge_cache: List[Challenge] = None
        super(Provider, self).__init__(*args, **kwargs)

    def _authenticate(self, username: str, password: str) -> None:

        # Build a requests session object
        s = requests.session()
        s.headers.update({"User-Agent": "flagr/3.0"})

        # Support API token authentication: password = "token:<api-token>"
        if password.startswith("token:"):
            api_token = password[len("token:"):]
            s.headers.update({"Authorization": f"Token {api_token}"})
            self.session = s
            self.csrf_token = None

            # Verify token works by fetching user profile
            r = self.session.get(f"{self.url}/api/v1/users/me")
            if r.status_code != 200:
                raise AuthenticationError(
                    f"API token authentication failed (status {r.status_code})"
                )

            data = r.json()["data"]
            self.me = User(
                name=data["name"],
                score=data.get("score", 0),
                ident=str(data["id"]),
                team=data.get("team", {}).get("name") if isinstance(data.get("team"), dict) else data.get("team"),
                solves=[],
            )
            return

        # Session-based authentication
        # Grab a nonce from the login page
        r = s.get(f"{self.url}/login")
        if r.status_code != 200:
            raise AuthenticationError(
                f"Received status code {r.status_code} from login page"
            )

        # Parse the nonce - try multiple formats for different CTFd versions
        nonce = None
        for pattern in ['name="nonce" value="', 'value="', "name='nonce' value='"]:
            try:
                nonce = r.text.split(f'name="nonce"')[1].split('value="')[1].split('"')[0]
                break
            except (IndexError, ValueError):
                continue

        if nonce is None:
            raise AuthenticationError("could not parse login nonce from CTFd")

        # Attempt authentication
        r = s.post(
            f"{self.url}/login",
            data={"name": username, "password": password, "nonce": nonce},
        )
        if r.status_code != 200:
            raise AuthenticationError(
                f"received status code {r.status_code} from login post"
            )

        # Grab the CSRF token - try multiple patterns for different CTFd versions
        self.csrf_token = None
        for pattern_start, pattern_end in [
            ('csrf_nonce = "', '"'),
            ("csrfNonce': \"", '"'),
            ("'csrfNonce': '", "'"),
            ('init.csrfNonce = "', '"'),
        ]:
            try:
                self.csrf_token = r.text.split(pattern_start)[1].split(pattern_end)[0]
                break
            except (IndexError, ValueError):
                continue

        # Save requests session
        self.session = s

        # Get user profile
        r = self.session.get(f"{self.url}/api/v1/users/me")
        if r.status_code != 200:
            raise RuntimeError("failed to retrieve profile")

        data = r.json()["data"]
        self.me = User(
            name=data["name"],
            score=data.get("score", 0),
            ident=str(data["id"]),
            team=data.get("team", {}).get("name") if isinstance(data.get("team"), dict) else data.get("team"),
            solves=[],
        )

    def _api_headers(self) -> Dict[str, str]:
        """Build headers for API requests, including CSRF token if available."""
        headers = {}
        if self.csrf_token:
            headers["CSRF-Token"] = self.csrf_token
        return headers

    @property
    def challenges(self) -> Generator[Challenge, None, None]:

        # Request the list of challenges
        r = self.session.get(f"{self.url}/api/v1/challenges")
        if r.status_code != 200:
            raise RuntimeError(f"failed to retrieve challenges (status {r.status_code})")

        # Extract json data
        data = r.json()["data"]

        # Grab solves
        try:
            solves = self._get_solves()
            solve_ids = {s.ident for s in solves}
        except Exception:
            solve_ids = set()

        # Iterate over challenges
        for c in data:
            challenge = Challenge(
                title=c["name"],
                value=c["value"],
                ident=str(c["id"]),
                provider=self,
                tags=[c.get("category", "")] + c.get("tags", []),
            )
            if challenge.ident in solve_ids:
                challenge.solved = True
            yield challenge

    @property
    def users(self) -> Generator[User, None, None]:

        # Request the scoreboard, which lists all users
        r = self.session.get(f"{self.url}/api/v1/scoreboard")
        if r.status_code != 200:
            raise RuntimeError("failed to get scoreboard")

        # Extract data
        data = r.json()["data"]

        # Yield all users
        for u in data:
            yield User(
                name=u["name"],
                score=u["score"],
                ident=u.get("account_id", u.get("id", "")),
                team=u.get("team"),
            )

    def _get_solves(self) -> List[Challenge]:
        """
        Get the list of solves for this user.
        :return: List of challenges we have solved
        """

        # Get user solves
        r = self.session.get(f"{self.url}/api/v1/users/me/solves")
        if r.status_code != 200:
            return []

        # Extract solve data
        data = r.json()["data"]
        solves = []
        for solve in data:
            challenge_data = solve.get("challenge", {})
            solves.append(
                Challenge(
                    title=challenge_data.get("name", ""),
                    value=challenge_data.get("value", 0),
                    ident=str(solve.get("challenge_id", "")),
                    provider=self,
                    tags=[challenge_data.get("category", "")],
                    solved=True,
                )
            )

        return solves

    def scoreboard(
        self, localize: User = None, count=10, bracket: Bracket = None
    ) -> Dict[int, User]:

        # Request the scoreboard, which lists all users
        r = self.session.get(f"{self.url}/api/v1/scoreboard")
        if r.status_code != 200:
            return {}

        # Extract data
        data = r.json()["data"]
        if not data:
            return {}

        # Assume we are starting at the top
        start = 0

        if localize is not None:
            for pos, u in enumerate(data):
                account_type = u.get("account_type", "user")
                if (account_type == "team" and u["name"] == localize.team) or (
                    account_type != "team" and u["name"] == localize.name
                ):
                    start = pos
                    break

        # Ideal world, grab this section of the scoreboard
        start -= int(count / 2)
        end = start + count

        # Account for under or overflow
        if start < 0:
            end -= start
            start = 0
        if end >= len(data):
            start -= end - len(data)
            end = len(data)
        if start < 0:
            start = 0

        return {
            (pos + start + 1): User(
                name=u["name"],
                score=u["score"],
                ident=str(u.get("account_id", u.get("id", ""))),
                team=u.get("team", u["name"]),
            )
            for pos, u in enumerate(data[start:end])
        }

    def get_challenge(self, ident: str) -> Challenge:

        # Request challenge details
        r = self.session.get(f"{self.url}/api/v1/challenges/{ident}")
        if r.status_code != 200:
            raise RuntimeError(f"failed to get challenge details (status {r.status_code})")

        # Extract data
        data = r.json()["data"]

        # Build file URLs - handle both relative and absolute URLs
        files = {}
        for f in data.get("files", []):
            filename = f.split("?")[0].split("/")[-1]
            if f.startswith("http"):
                files[filename] = f
            else:
                files[filename] = f"{self.url}{f}"

        # Parse connection info from description for remote challenges
        description = data.get("description", "")

        # Build challenge structure
        challenge = Challenge(
            title=data["name"],
            value=data["value"],
            ident=str(data["id"]),
            provider=self,
            description=description,
            files=files,
            tags=[data.get("category", "")] + data.get("tags", []),
        )

        # Set solved flag
        try:
            solves = self._get_solves()
            if challenge.ident in {c.ident for c in solves}:
                challenge.solved = True
        except Exception:
            pass

        # Return challenge structure
        return challenge

    def submit(self, challenge: Challenge, flag: str) -> Tuple[bool, int]:

        # Attempt to submit flag
        r = self.session.post(
            f"{self.url}/api/v1/challenges/attempt",
            json={"challenge_id": challenge.ident, "submission": flag},
            headers=self._api_headers(),
        )
        if r.status_code != 200:
            raise RuntimeError(f"failed to submit flag (status {r.status_code})")

        # Check if it was right
        data = r.json()["data"]
        if data["status"] != "incorrect":
            challenge.solved = True
            return True, 1
        else:
            return False, 1
