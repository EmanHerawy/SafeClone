#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='safe-package',
    version='1.0.0',
    description='A safe Python package',
    author='Safe Author',
    author_email='safe@example.com',
    packages=find_packages(),
    install_requires=[
        'requests>=2.25.0',
        'click>=7.0.0',
    ],
    entry_points={
        'console_scripts': [
            'safe-cli=safe_package.cli:main',
        ],
    },
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],
)
