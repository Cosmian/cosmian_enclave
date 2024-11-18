# Cosmian Enclave application example

A basic example of a Cosmian Enclave application containing:
- Simple helloworld Flask application
- Cosmian Enclave config file
- Unit tests

You should edit the following files:
- `src/` with your own webservice code
- `Dockerfile` to run your webservice code into a Docker
- `config.toml` to specify some details for the person who will run your code through the `cenclave` cli
- `tests` with the tests code which can be run against your webservice
- `secrets_to_seal.json` and `secrets.json` if necessary to specify your app secrets (when using `cenclave`)

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
