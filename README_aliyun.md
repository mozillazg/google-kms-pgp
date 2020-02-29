# Aliyun KMS PGP

## Build

```bash
go build -o aliyun-kms-pgp
```

## Usage

Create an kms key with `RSA_2048` KeySpec and `SIGN/VERIFY` Purpose.

### Usage: Generating a Key

```bash
$ export ALIBABA_CLOUD_REGION_ID=<REGION_ID>
$ export ALIBABA_CLOUD_ACCESS_KEY_ID=<ACCESS_KEY_ID>
$ export ALIBABA_CLOUD_ACCESS_KEY_SECRET=<ACCESS_KEY_SECRET>
$ KMS_KEY_ID=<key-id>
$ KMS_KEY_VERSION_ID=<key-version-id>

$ ./aliyun-kms-pgp --key-id=${KMS_KEY_ID} \
  --key-version-id=${KMS_KEY_VERSION_ID} \
  --armor --export -o my-public-key.asc

$ gpg --import my-public-key.asc
gpg: key 60D5A687078FC103: public key "<key-id>:<key-version-id>" imported
gpg: Total number processed: 1
gpg:               imported: 1


```

### Usage: Signing

```bash
$ export ALIBABA_CLOUD_REGION_ID=<REGION_ID>
$ export ALIBABA_CLOUD_ACCESS_KEY_ID=<ACCESS_KEY_ID>
$ export ALIBABA_CLOUD_ACCESS_KEY_SECRET=<ACCESS_KEY_SECRET>
$ KMS_KEY_ID=<key-id>
$ KMS_KEY_VERSION_ID=<key-version-id>

$ echo 'test' > message.txt
$ ./aliyun-kms-pgp --key-id=${KMS_KEY_ID} \
  --key-version-id=${KMS_KEY_VERSION_ID} \
  --armor --detach-sign message.txt

$ gpg --verify message.txt.asc message.txt
gpg: Signature made Sat Feb 29 18:06:03 2020 CST
gpg:                using RSA key 60D5A687078FC103
gpg: Good signature from "<key-id>:<key-version-id>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: E96A 16BE 400A A9A9 2E3A  FA54 60D5 A687 078F C103
```
