#!/usr/bin/env python3

from __future__ import print_function
import sys
from setuptools import setup

if sys.version_info < (3,3):
    sys.exit("Python 3.3 or newer is required.")

setup(name="rsa_ct_kip",
      version="0.4",
      description="Provision an RSA SecurID token with RSA's CT-KIP protocol",
      author="Daniel Lenski",
      author_email="dlenski@gmail.com",
      license='MIT',
      url="https://github.com/dlenski/rsa_ct_kip",
      packages=["rsa_ct_kip"],
      install_requires=['pycryptodome>=3.4.7', 'requests>=2.0'],
      entry_points={ 'console_scripts': [ 'rsa_ct_kip=rsa_ct_kip.client:main' ] }
      )
