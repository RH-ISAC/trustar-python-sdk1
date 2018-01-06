==============================
Python SDK for the TruSTAR API
==============================

See https://docs.trustar.co/ for the official documentation to the TruSTAR Python SDK.


Installation/Upgrade
--------------------

Pre-requisites
~~~~~~~~~~~~~~

Make sure you have the latest version of Requests package
::

  $ sudo pip install requests --upgrade

Using pip (recommended)
~~~~~~~~~~~~~~~~~~~~~~~

::

  $ pip install trustar --upgrade


Manual
~~~~~~

1. Get the latest SDK by downloading as a [ZIP](https://github.com/trustar/trustar-python/archive/master.zip) and extract locally.  You can also clone the repository directly from [GitHub](https://github.com/trustar/trustar-python)

2. Install requirements

  - Python 2.7+:
    ::

    $ sudo pip install future python-dateutil pytz requests configparser

  - Python 3:
    ::

    $ sudo pip3 install future python-dateutil pytz requests configparser

3. Install SDK

::

    $ cd trustar-python
    $ python setup.py install --force

Uninstallation
--------------
::

    $ pip uninstall trustar


Running examples and tests
--------------------------
- Retrieve or generate API credentials from the TruSTAR Station: https://station.trustar.co/settings/api
- Inside the ``examples`` directory, create your own ``trustar.conf`` file from ``trustar.conf.example`` and Copy in your credentials and enclave IDs

::

    $ cd examples
    $ python basic_usage.py
    $ python3 basic_usage.py


API Documentation
-----------------

See https://docs.trustar.co/ for full API documentation.


