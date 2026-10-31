# Raes

A hybrid encryption tool that uses the RSA algorithm to encrypt the AES key and the AES algorithm to encrypt the entire file.

## Install 

```bash
git clone https://github.com/fovlin/raes
cd raes
go build .
```

## usage

```bash
raes gen-key
# generate a private key and public key on $HOME/.raes directory

raes enc <file> [output]

raes dec <encfile> [output]
```
