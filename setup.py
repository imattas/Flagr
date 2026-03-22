#!/usr/bin/env python

import os
from setuptools import find_packages
from setuptools import setup

def _read_version():
    vf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")
    if os.path.exists(vf):
        with open(vf) as f:
            return f.read().strip()
    return "3.0"

dependencies = [
    "wheel",
    "requests",
    "python-magic",
    "pillow",
    "jinja2",
    "pyenchant",
    "pycryptodome",
    "pytesseract",
    "dulwich",
    "beautifulsoup4",
    "base58",
    "pysocks",
    "scipy",
    "pydub",
    "matplotlib",
    "PyPDF2",
    "pyopenssl",
    "primefac",
    "gmpy2",
    "cmd2>=2.0.0",
    "watchdog",
    "pygments",
    "regex",
    "colorama",
    "pyperclip",
    "pwntools",
]

# Setup
setup(
    name="flagr",
    version=_read_version(),
    python_requires=">=3.8",
    description="Automatic Capture the Flag Problem Solver",
    author="John Hammond/Caleb Stewart",
    url="https://github.com/imattas/Flagr",
    packages=find_packages(),
    package_data={"flagr": ["templates/*"]},
    entry_points={"console_scripts": ["flagr=flagr.cli:main"]},
    install_requires=dependencies,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
