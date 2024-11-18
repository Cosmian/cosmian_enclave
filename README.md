# Cosmian Enclave

## Overview

Cosmian Enclave allows to easily run confidential Python web applications based on [Intel® SGX](https://www.intel.com/content/www/us/en/products/docs/accelerator-engines/software-guard-extensions.html) and [Gramine](https://gramine.readthedocs.io/en/latest/).
Its features include the ability to encrypt the code and the construction of a [RA-TLS](https://arxiv.org/pdf/1801.05863) channel with your enclave.

Read [Cosmian Enclave documentation](https://docs.cosmian.com/compute/cosmian_enclave/overview/) for more details.

## Command-Line Interface

Cosmian Enclave CLI [cenclave](cli/cenclave) helps to deploy your confidential web application and provides tooling for encryption with your enclave.
Check [intel-sgx-ra](https://github.com/Cosmian/intel-sgx-ra) if you just need to do the [remote attestation](https://en.wikipedia.org/wiki/Trusted_Computing#Remote_attestation) of the enclave as a client.
