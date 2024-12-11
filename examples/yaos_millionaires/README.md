# Yao's Millionaires application example

[Yao's Millionaires' problem](https://en.wikipedia.org/wiki/Yao%27s_Millionaires%27_problem) solved using Cosmian Enclave.
Each participant reprensented by its public key can send the value of its wealth to know who is the richest.
The result is encrypted using participant's public key.

## Prequisites

### Setup

First, each participant generates a keypair to identify with their own public/private key:

```console
$ cenclave keygen --asymmetric --output /tmp/keypair1.bin
Public key: c12ace0ca954b883fa918561dd647cf3de79861ea5996b6d2e4e4e8abc664a26
Public key (Base64): wSrODKlUuIP6kYVh3WR88955hh6lmWttLk5OirxmSiY=
Keypair wrote to /tmp/keypair1.bin
$ cenclave keygen --asymmetric --output /tmp/keypair2.bin
Public key: 4afc6cfc76abc1715bf7f89f451d3bdfcb76883db7d420ecf6295b9975c35a20
Public key (Base64): Svxs/HarwXFb9/ifRR0738t2iD231CDs9ilbmXXDWiA=
Keypair wrote to /tmp/keypair2.bin
```

then populate `src/config.json` with participant's public key base64-encoded:

```console
{
    "participants": [
      "wSrODKlUuIP6kYVh3WR88955hh6lmWttLk5OirxmSiY=",
      "Svxs/HarwXFb9/ifRR0738t2iD231CDs9ilbmXXDWiA="
    ]
}
```

### Test the code locally without SGX (docker required)

```console
$ cenclave localtest --code src/ \
                     --dockerfile Dockerfile \
                     --config config.toml \
                     --test tests/
```

### Create an archive for Cosmian Enclave

```console
$ cenclave package --code src/ \
                   --dockerfile Dockerfile \
                   --config config.toml \
                   --test tests/ \
                   --output tarball/
```

The generated tarball file in `tarball/` folder can now be used on the SGX machine properly configured with Cosmian Enclave.

Optionally use `--encrypt` if you want the code to be encrypted.

## Running the code with Cosmian Enclave

### Spawn the configuration server

```console
$ cenclave spawn --host <HOST> --port <PORT> --size <ENCLAVE_SIZE> --package <TARBALL_FILE> --output sgx_operator/ --san <EXTERNAL_IP | DOMAIN_NAME | localhost> yaos_millionaires
```

- `host`: usually 127.0.0.1 for localhost or 0.0.0.0 to expose externally
- `port`: network port used by your application, usually 9999
- `size`: memory size (in MB) of the enclave (must be a power of 2 greater than 2048)
- `package`: tarball file with the code and container image
- `san`: [Subject Alternative Name](https://en.wikipedia.org/wiki/Public_key_certificate#Subject_Alternative_Name_certificate) used for routing with SSL pass-through (either domain name, external IP address or localhost)

### Seal code secret key (optionally)

If you choose to encrypt the code with `--encrypt` then you need to verify your enclave first.
Ask the SGX operator to communicate the `evidence.json` file to do the remote attestation and verify that your code is running in the enclave:

```console
$ cenclave verify --evidence evidence.json --package tarball/package_<><>.tar --output ratls.pem
```

if successful, then include the randomly generated secret key in `secrets_to_seal.json`:

```text
{
    "code_secret_key": "HEX_CODE_SECRET_KEY"
}
```

and finally seal `secrets_to_seal.json` file:

```console
$ cenclave seal --input secrets_to_seal.json --receiver-enclave ratls.pem --output code_provider/sealed_secrets.json.enc
```

### Run your application

```console
$ cenclave run yaos_millionaires
```

Note: if the code is encrypted, sealed secrets must be added to the command with `--sealed-secrets sealed_secrets.json.enc`.

### Use the client

In the `client/` directory you can use the Python client to query your enclave:

```console
$ # Verify the remote enclave and the MRENCLAVE hash digest
$ python main.py --verify https://<HOST>:<PORT>
$
$ # list participants
$ python main.py --keypair /tmp/keypair1.bin --list https://<HOST>:<PORT>
$
$ # push your fortune
$ python main.py --keypair /tmp/keypair1.bin --push 1_000_000 https://<HOST>:<PORT>
$ python main.py --keypair /tmp/keypair1.bin --push 2_000_000 https://<HOST>:<PORT>
$
$ # ask who is the richest with keypair1 (result encrypted for keypair1)
$ python main.py --keypair /tmp/keypair1.bin --result https://<HOST>:<PORT>
$ # ask who is the richest with keypair2 (result encrypted for keypair2)
$ python main.py --keypair /tmp/keypair2.bin --result https://<HOST>:<PORT>
```
