# git tag 0.0.14 -m "Bump version to 0.0.14" && git push --tags
# python setup.py register -r pypitest
# python setup.py sdist upload -r pypitest
# python setup.py register -r pypi
# python setup.py sdist upload -r pypi

from setuptools import setup, find_packages

setup(
    name='trustar',
    # packages= ['trustar'],
    version='0.0.14',
    author='TruSTAR Technology Inc.',
    author_email='support@trustar.co',
    url='https://github.com/trustar/trustar-python',
    download_url='https://github.com/trustar/trustar-python/tarball/0.0.14',
    description='Python SDK for the TruSTAR REST API',
    license='MIT',
    install_requires=['future',
                      'python-dateutil',
                      'pytz',
                      'requests',
                      'configparser', 'unicodecsv', 'pdfminer', 'tzlocal'],
    # package source directory
    # package_dir={'': 'trustar'},
    packages=find_packages(),
    use_2to3=True
)
