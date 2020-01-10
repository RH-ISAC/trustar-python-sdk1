# Python SDK for the TruSTAR API

## API/SDK Documentation

See https://docs.trustar.co/ for the official documentation to the TruSTAR Python SDK.


## Installation

### Install
To install, run

```bash
pip install trustar
```

### Upgrade
If the package has been previously installed, upgrade to the latest version with

```bash
pip install --upgrade trustar
```

### Uninstall
To uninstall, simply run

```bash
pip uninstall trustar
```


## Tutorial and Examples

For a quick tutorial on using this package, follow the guide at https://docs.trustar.co/sdk/quick_start.html.

More examples can be found within this repository under `trustar/examples`

## Development

To setup this project for development, you must create a virtual environment and pip install the package in editable mode.
This will also install any transitive requirements automatically.

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

### Python 2/3 Compatibility

This package is compatible with both Python 2 and 3.  Ensure that any changes made maintain this cross-compatibility.
