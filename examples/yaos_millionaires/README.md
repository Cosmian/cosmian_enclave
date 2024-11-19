# Yao's Millionaires application example

Yao's Millionaires problem solved using Cosmian Enclave.
Each participant reprensented by its public key can send the value of its wealth to known who is the richest.
The result is encrypted for each public key.

## Test your app before creating the enclave

```console
$ cenclave localtest --code src/ \
                     --dockerfile Dockerfile \
                     --config config.toml \
                     --test tests/
```

## Create Cosmian Enclave package with the code and the container image

```console
$ cenclave package --code src/ \
                   --dockerfile Dockerfile \
                   --config config.toml \
                   --test tests/ \
                   --output code_provider
```

The generated package can now be sent to the SGX operator.
