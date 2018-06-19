"""MQTToRRD package installation."""
from setuptools import setup

from mqttorrd import __name__ as name, __version__, __author__, \
    __email__, __license__, __doc__ as description

REQUIRES = []
with open("requirements.txt", "r") as requires:
    for line in requires:
        REQUIRES.append(line.strip())


def doc():
    """Return README.rst content."""
    with open("README.rst", "r", encoding="utf-8") as readme:
        return readme.read().strip()


setup(
    name=name,
    version=__version__,
    author=__author__,
    author_email=__email__,
    description=description,
    long_description=doc(),
    long_description_content_type="text/x-rst",
    url="https://github.com/ondratu/mqttorrd",
    license=__license__,
    scripts=["mqttorrd.py"],
    data_files=[("share/doc/mqttorrd",
                 ["README.rst", "COPYING", "ChangeLog", "AUTHORS",
                  "CONTRIBUTION.rst"]),
                ("share/doc/mqttorrd/example", ["mqttorrd.ini"])],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: No Input/Output (Daemon)",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: System :: Monitoring"],
    python_requires=">=3.5",
    setup_requires=REQUIRES,
    install_requires=REQUIRES,
)
