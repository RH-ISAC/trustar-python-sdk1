# git tag 0.3.14 -m "Bump version" && git push --tags origin master
# python setup.py sdist
# twine upload --skip-existing dist/*

from setuptools import setup, find_packages
from glob import glob

# read version
version_globals = {}
with open("trustar/version.py") as fp:
    exec(fp.read(), version_globals)
version = version_globals['__version__']

setup(
    name='trustar',
    packages=find_packages(),
    version=version,
    author='TruSTAR Technology, Inc.',
    author_email='support@trustar.co',
    url='https://github.com/trustar/trustar-python',
    download_url='https://github.com/trustar/trustar-python/tarball/%s' % version,
    description='Python SDK for the TruSTAR REST API',
    license='MIT',
    install_requires=['future',
                      'python-dateutil',
                      'pytz',
                      'requests',
                      'configparser',
                      'unicodecsv',
                      'tzlocal',
                      'PyYAML',
                      'six'
                      ],
    include_package_data=True,
    scripts=glob('trustar/examples/**/*.py') + glob('trustar/examples/*.py'),
    use_2to3=True
)
