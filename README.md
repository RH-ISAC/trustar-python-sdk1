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

To setup this project for development, you need to have [pipenv](https://pipenv.pypa.io/en/latest/) installed and follow the next instructions:

1. Setup a virtual environment:
    ```bash
    pipenv install --dev
    ```

2. Activate the virtualenv:
    ```bash
    pipenv shell
    ```
3. Install this package in editable mode:
    ```bash
    pip install -e .
    ```

Should you need to create a requirements.txt file to manage a Python 2.7 virtualenv do:

```bash
pipenv run pip freeze > requirements.txt
```

Note: you can use pipenv too to create a 2.7 venv, check the pipenv docs for that.

### Python 2/3 Compatibility

This package is compatible with both Python 2 and 3.  Ensure that any changes made maintain this cross-compatibility.
