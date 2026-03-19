#!/usr/bin/env bash
# Check for flagr updates and then run Flagr

function failure
{
	echo "[!] error: $*"
	exit 1
}

function update_flagr
{

	# Prompt if user wants to update
	declare -- ANSWER=;
	until [[ $ANSWER =~ [yYnN] ]]; do
		read -rp "[?] update flagr (y/n): " ANSWER
	done

	if ! [[ $ANSWER =~ [yY] ]]; then
		echo "[*] skipping update"
		return
	fi

	echo "[+] installing flagr upgrades"

	# Grab new changes
	git pull || failure "git pull failed"

	# Run pip installer just in case
	pip install -r requirements.txt || failure "pip install failed"
}

# Ensure we are in the repo
cd /flagr

# Check for updates to current branch
echo "[+] checking for updates"

git remote update >/dev/null
if git status -uno | grep "branch is up to date with" >/dev/null; then
	echo "[+] flagr is up to date!"
else
	echo "[*] newer flagr version avaiable (you should rebuild your docker)"
	update_flagr
fi

# Run flagr
python -m flagr "$@"
