from setuptools import setup, find_packages
from pathlib import Path

long_description = (Path(__file__).parent / "README.md").read_text()

setup(
    name="webraider",
    version="1.0.0",
    author="WebRaider",
    description="CLI Web Pentesting Toolkit for Kali Linux",
    license="MIT",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
        "requests>=2.31",
        "python-whois>=0.9",
        "dnspython>=2.4",
        "urllib3>=2.0",
        "beautifulsoup4>=4.12",
    ],
    entry_points={
        "console_scripts": [
            "webraider=webraider.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Topic :: Security",
    ],
)
