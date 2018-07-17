# Python SDK for the TruSTAR API

## API/SDK Documentation

See https://docs.trustar.co/ for the official documentation to the TruSTAR Python SDK.


## Installation/Upgrade

### Pre-requisites

Make sure you have the latest version of Requests package

```bash
$ sudo pip install requests --upgrade
```

### Using pip (recommended)

```bash
$ pip install trustar --upgrade
```


### Manual Installation

1. Get the latest SDK by downloading as a [ZIP](https://github.com/trustar/trustar-python/archive/master.zip) and extract locally.  You can also clone the repository directly from [GitHub](https://github.com/trustar/trustar-python)

2. Install requirements

* Python 2.7+:
```bash
$ sudo pip install future python-dateutil pytz requests configparser
```

* Python 3:
```bash
$ sudo pip3 install future python-dateutil pytz requests configparser
```

3. Install SDK
```bash
$ cd trustar-python
$ python setup.py install --force
```

Uninstallation
--------------
```bash
$ pip uninstall trustar
```


Running examples and tests
--------------------------
- Retrieve or generate API credentials from the TruSTAR Station: https://station.trustar.co/settings/api
- Inside the ``examples`` directory, create your own ``trustar.conf`` file from ``trustar.conf.example`` and Copy in your credentials and enclave IDs

```bash
$ cd examples
$ python basic_usage.py
$ python3 basic_usage.py
```


## Development

To setup this project for development:

1. Create a virtualenv using python 3:
```bash
virtualenv --no-site-packages -p python3 venv3
```
2. Activate the virtualenv:
```bash
source ./venv3/bin/activate
```
3. Install this package in editable mode:
```bash
pip install -e .
```
4. Although step 3 will install the core requirements for the package, some additional packages are used during
development (specifically, ``nose``).  To install these, run
```bash
pip install -r requirements.txt
```
