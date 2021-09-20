#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages #type: ignore

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    'varint>=1.0.2',  # tested with 1.0.2
    'six>=1.10.0',    # tested with 1.16.0
    'base58>=1.0.2',  # tested with 2.1.0
    'pyskein>=1.0'    # tested with 1.0
]

setup_requirements = ['pytest-runner', ]

test_requirements = [
    'pytest',
    'pytest-cov',
    # TODO: put package test requirements here
]

setup(
    name='py-multihash',
    version='2.0.0',
    description="Multihash implementation in Python",
    long_description=readme + '\n\n' + history,
    author="Dhruv Baldawa",
    author_email='dhruv@dhruvb.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        "Typing :: Typed",

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    install_requires=requirements,
    license="MIT license",
    include_package_data=True,
    keywords='multihash',
    packages=find_packages(include=['multihash']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/multiformats/multihash',
    zip_safe=False,
    package_data={"": [],
                  "multihash": ["multihash/py.typed"],
                 },
)
