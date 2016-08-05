# TruSTAR Python SDK and sample codes for the TruSTAR API 


## Requirements
* json
* pandas
 
```shell
    pip install pandas
```

## Installation
```shell
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
