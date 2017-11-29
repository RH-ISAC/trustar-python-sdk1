# git tag 0.2.5 -m "Bump version" && git push --tags origin master
# python setup.py sdist
# twine upload --skip-existing dist/*

from distutils.core import setup

setup(
    name='trustar',
    packages=['trustar'],
    version='0.2.5',
    author='TruSTAR Technology, Inc.',
    author_email='support@trustar.co',
    url='https://github.com/trustar/trustar-python',
    download_url='https://github.com/trustar/trustar-python/tarball/0.2.5',
    description='Python SDK for the TruSTAR REST API',
    license='MIT',
    install_requires=['future',
                      'python-dateutil',
                      'pytz',
                      'requests',
                      'configparser',
                      'unicodecsv',
                      'tzlocal'
                      ],

    use_2to3=True
)
