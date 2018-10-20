#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    'varint>=1.0.2,<2.0',
    'six>=1.10.0,<2.0',
    'morphys>=1.0,<2.0',
    'base58>=1.0.2,<2.0',
]

setup_requirements = ['pytest-runner', ]

test_requirements = [
    'pytest',
    'pytest-cov',
    # TODO: put package test requirements here
]

setup(
    name='py-multihash',
    version='0.2.1',
    description="Multihash implementation in Python",
    long_description=readme + '\n\n' + history,
    author="Dhruv Baldawa",
    author_email='dhruv@dhruvb.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
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
)
