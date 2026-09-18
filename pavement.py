# -*- coding: utf-8 -*-
"""Config-like for paver tool."""
from paver.easy import task, sh  # noqa


@task
def lint():
    """Check code style and conventions."""
    sh('prospector')


@task
def coverage():
    """Run tests and collect coverage."""
    sh('pytest --cov -- tests/unit')
    sh('coverage xml')
