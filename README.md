# Python SDK for the TruSTAR API 

## Requirements 
Python 2.7+:
  ```shell
  $ pip install future pandas python-dateutil pytz requests configparser
  ``` 
Python 3:
  ```shell
  $ pip3 install future pandas  python-dateutil pytz requests configparser
  ``` 
  
## Installation

### Using pip (recommended)
  ```shell
  $ pip install trustar
  ``` 
### Manual
Get the latest SDK by downloading as a [ZIP](https://github.com/trustar/trustar-python/archive/master.zip) and extract locally.  You can also clone the repository directly from [GitHub](https://github.com/trustar/trustar-python)
  ```shell   
   $ cd trustar-python
   $ python setup.py install --force
   ```
 
## Uninstallation
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
