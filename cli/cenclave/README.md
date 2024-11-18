# Cosmian Enclave Command-Line Interface

## Overview

Cosmian Enclave allows to easily run confidential Python web applications based on [Intel® SGX](https://www.intel.com/content/www/us/en/products/docs/accelerator-engines/software-guard-extensions.html) and [Gramine](https://gramine.readthedocs.io/en/latest/).
Its features include the ability to encrypt the code and the construction of a [RATLS](https://arxiv.org/pdf/1801.05863) channel with your enclave.

Read [Cosmian Enclave documentation](https://docs.cosmian.com/compute/cosmian_enclave/overview/) for more details.

## Install

```console
$ pip install cenclave
```

## Usage

```console
$ cenclave -h
```

Note: if you set the env variable `BACKTRACE=full`, a Python stacktrace will be printed in case of errors.

### Scaffold your app

__User__: the code provider

```console
$ cenclave scaffold example
```

### Test your app before ceating the enclave

__User__: the code provider

```console
$ cenclave localtest --project example/
```

### Create the Cosmian Enclave package with the code and the docker image

__User__: the code provider

```console
$ cenclave package --project example/ \
                   --output workspace/code_provider 
```

The generated package can now be sent to the sgx operator.

### Spawn the Cosmian Enclave docker

__User__: the SGX operator

```console
$ cenclave spawn --host 127.0.0.1 \
                 --port 9999 \
                 --size 4096 \
                 --package workspace/code_provider/package_cenclave_src_1683276327723953661.tar \
                 --output workspace/sgx_operator/ \
                 app_name
```

At this moment, evidences have been automatically collected and the web application is up.

Evidences are essential for the code provider to verify the trustworthiness of the running application.

The file `workspace/sgx_operator/evidence.json` can now be shared with the other participants.

### Check the trustworthiness of the application

__User__: the code provider

The trustworthiness is established based on multiple information:

- the full code package (tarball)
- the arguments used to spawn the web app
- evidences captured from the enclave

Verification of the enclave information:

```console
$ cenclave verify --package workspace/code_provider/package_cenclave_src_1683276327723953661.tar \
                  --evidence output/evidence.json \
                  --output /tmp
```

If the verification succeeds, you get the RA-TLS certificate (written as a file named `ratls.pem`) and you can now seal
the code key to share it with the SGX operator.

### Seal your secrets

__User__: the code provider

```console
$ cenclave seal --secrets example/secrets_to_seal.json \
                --cert /tmp/ratls.pem \
                --output workspace/code_provider/
```

### Finalize the configuration and run the application

__User__: the SGX operator

```console
$ cenclave run --sealed-secrets workspace/code_provider/secrets_to_seal.json.sealed \
               app_name
```

### Test the deployed application

__User__: the SGX operator

```console
$ cenclave test --test workspace/sgx_operator/tests/ \
                --config workspace/sgx_operator/config.toml \
                app_name
```

### Decrypt the result

__User__: the code provider

Assume the SGX operator gets a result as follows: `curl https://localhost:7788/result --cacert /tmp/ratls.pem > 
result.enc`

Then, the code provider can decrypt the result as follows:

```console
$ cenclave decrypt --key key.txt \
                   --output workspace/code_provider/result.plain \
                   result.enc
$ cat workspace/code_provider/result.plain
```

### Manage Cosmian Enclave's containers

__User__: the SGX operator

You can stop and remove the container as follows:

```console
$ cenclave stop [--remove] <app_name>
```

You can restart a stopped and not removed containers as follows:

```console
$ cenclave restart <app_name>
```

You can get the Cosmian Enclave container logs as follows:

```console
$ cenclave logs <app_name>
```

You can get the Cosmian Enclave docker status as follows:

```console
$ cenclave status <app_name>
```

You can get the list of running Cosmian Enclave containers:

```console
$ cenclave list
```
