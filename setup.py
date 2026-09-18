# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

from termius import __version__


cli_command_name = 'termius'

requires = [
    'requests>=2.7.0',
    'cryptography>=3.2',
    'six>=1.10.0',
    'cached-property>=1.3.0',
    'paramiko>=1.16.0',
    'pathlib2>=2.1.0',
    'blinker>=1.4',
    'pynacl>=1.5.0',
    'python-socketio>=5.11.0',
    'websocket-client>=1.6.0',
]


def get_long_description():
    try:
        import pypandoc
        return pypandoc.convert('README.md', 'rst')
    except (IOError, ImportError):
        with open('README.md') as handle:
            return handle.read()


setup(
    name='termius',
    version=__version__,
    license='BSD',
    author='Termius Corporation',
    author_email='hello@termius.com',
    url='https://github.com/MiaM1ku/termius-mcp',
    description='Termius Cloud MCP server.',
    long_description=get_long_description(),
    keywords=['termius', 'mcp'],
    packages=find_packages(exclude=['tests']),
    install_requires=requires,
    python_requires='>=3.9',
    zip_safe=False,
    include_package_data=True,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: Unix',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Utilities',
    ],
    entry_points={
        'console_scripts': [
            '{} = termius.main:main'.format(cli_command_name)
        ],
    },
)
