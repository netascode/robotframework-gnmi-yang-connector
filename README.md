# GnmiYangConnector

A gNMI and YANG connector library for Robot Framework.

## Overview

GnmiYangConnector provides a Robot Framework library for interacting with network devices using gNMI (gRPC Network Management Interface) protocol and YANG data models.

## Features

- gNMI protocol support
- YANG model parsing and validation
- Robot Framework keyword library
- Python 3.10+ support

## Installation

```bash
pip install robotframework-gnmi-yang-connector
```

## Development

### Setup

This project uses Poetry for dependency management and packaging.

```bash
# Install dependencies
poetry install

# Run tests
poetry run pytest

# Run linting and formatting
make prepush
```

### Pre-commit Hooks

Pre-commit hooks are configured to run code quality checks before commits:

```bash
pre-commit install
```

## Testing

Run tests with pytest:

```bash
poetry run pytest
```

## License

See LICENSE file for details.
