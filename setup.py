# git tag 0.3.11 -m "Bump version" && git push --tags origin master
# python setup.py sdist
# twine upload --skip-existing dist/*

from distutils.core import setup

# read version
version_globals = {}
with open("trustar/version.py") as fp:
    exec(fp.read(), version_globals)
version = version_globals['__version__']

setup(
    name='trustar',
    packages=['trustar', 'trustar.models'],
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

    use_2to3=True
)
