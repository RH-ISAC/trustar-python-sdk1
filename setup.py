# git tag 0.1.1 -m "Bump version" && git push --tags origin master
# python setup.py register -r pypitest
# python setup.py sdist upload -r pypitest
# python setup.py register -r pypi
# python setup.py sdist upload -r pypi

#from setuptools import setup, find_packages
from distutils.core import setup

setup(
    name='trustar',
    packages= ['trustar'],
    version='0.1.1',
    author='TruSTAR Technology, Inc.',
    author_email='support@trustar.co',
    url='https://github.com/trustar/trustar-python',
    download_url='https://github.com/trustar/trustar-python/tarball/0.1.1',
    description='Python SDK for the TruSTAR REST API',
    license='MIT',
    install_requires=['future',
                      'python-dateutil',
                      'pytz',
                      'requests',
                      'configparser',
                      'unicodecsv',
                      'tzlocal',
                      'python-dateutil'
                      ],

    use_2to3=True
)
