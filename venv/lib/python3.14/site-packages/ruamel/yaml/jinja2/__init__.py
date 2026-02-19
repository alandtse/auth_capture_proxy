# coding: utf-8

from __future__ import print_function, absolute_import, division, unicode_literals

_package_data = dict(
    full_package_name='ruamel.yaml.jinja2',
    version_info=(0, 2, 7),
    __version__='0.2.7',
    author='Anthon van der Neut',
    author_email='a.van.der.neut@ruamel.eu',
    description='jinja2 pre and post-processor to update with YAML',
    entry_points=None,
    license='MIT',
    since=2017,
    # status="α|β|stable",  # the package status on PyPI
    # data_files="",
    universal=True,
    keywords='yaml 1.2 parser round-trip jinja2',
    nested=True,
    install_requires=['ruamel.yaml>=0.16.1'],
    python_requires='>=3.6',
    tox=dict(env='3'),
)


version_info = _package_data['version_info']
__version__ = _package_data['__version__']
