# USSO-Client

The USSO-Client provides a universal single sign-on (SSO) integration for microservices, making it easy to add secure, scalable authentication across different frameworks. This client simplifies the process of connecting any microservice to the USSO service.

## Features

- **Core SSO Integration**: Use the USSO core client for basic SSO functionality across any Python application.
- **Framework-Specific Modules**:
  - **FastAPI Integration**: Specialized support for FastAPI applications, enabling async authentication mechanisms tailored to FastAPI's event loop.
  - *Django Integration* (Coming soon): Customizable Django authentication backend that integrates seamlessly with Django's user management and middleware architecture.

## Installation

Install the USSO client using pip:

```bash
pip install usso-client
```

To add framework-specific support, use the following commands:

For FastAPI:

```bash
pip install "usso-client[fastapi]"
```

## Quick Start
Follow the quick start guides in the documentation to integrate USSO in your application.

## Contributing
Contributions are welcome! See CONTRIBUTING.md for more details on how to get involved.

## License
Distributed under the MIT License. See LICENSE for more information.