# Python SDK for the TruSTAR API 
*Beta version*

## Requirements
Here's how to get started most quickly

### Python modules
* [pandas](http://pandas.pydata.org/pandas-docs/stable/install.html) python module
* pytz
* requests
* python-dateutil
 
Python 2.7+:
  ```shell
  $ pip install pandas python-dateutil pytz requests
  ``` 
  
Python 3:
  ```shell
  $ pip3 install pandas  python-dateutil pytz requests
  ``` 
  
  
### TruSTAR SDK
Get the latest SDK by downloading as a [ZIP](https://github.com/trustar/trustar-python/archive/master.zip) and extract locally.  You can also clone the repository directly from [GitHub](https://github.com/trustar/trustar-python)

Use **setup.py** on the downloaded source files:

    $ python setup.py install --force
    
    
### Uninstallation
```shell
$ pip uninstall trustar
```

## Running examples and tests
- Retrieve or generate API credentials from the TruSTAR Station: https://station.trustar.co/settings/api
- Inside the `examples` directory, create your own `trustar.conf` file from `trustar.conf.example` and Copy in your credentials and enclave ID 

```shell
    $ cd examples
    $ python basic_usage.py
```
## API Documentation

See https://github.com/trustar/public/wiki/TruSTAR-API for full API documentation
