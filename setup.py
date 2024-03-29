#!/usr/bin/env python3

import sys
from setuptools import setup

if sys.version_info < (3, 3):
    sys.exit("Python 3.3 or newer is required.")

setup(
    name="rsa_ct_kip",
    version="0.7",
    description="Provision an RSA SecurID token with RSA's CT-KIP protocol",
    author="Daniel Lenski",
    author_email="dlenski@gmail.com",
    license='MIT',
    url="https://github.com/dlenski/rsa_ct_kip",
    packages=["rsa_ct_kip"],
    install_package_data=True,
    package_data={"rsa_ct_kip": ["rsaprivkey.pem"]},
    install_requires=open('requirements.txt').readlines(),
    tests_require=open('requirements-test.txt').readline(),
    entry_points={'console_scripts': ['rsa_ct_kip=rsa_ct_kip.client:main']},
    test_suite='nose2.collector.collector',
)
