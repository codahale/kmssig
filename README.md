# kmssig

[![Build Status](https://travis-ci.org/codahale/kmssig.svg?branch=master)](https://travis-ci.org/codahale/kmssig)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/codahale/kmssig/blob/master/LICENSE)

`kms-sig` is a utility for signing and verifying files on AWS using the
Key Management Service (KMS). Unlike asymmetric digital signature
schemes (e.g. RSA, DSA), `kms-sig`'s security depends on KMS
permissions.

## WARNING

**This project has not been reviewed by security professionals. Its
  internals, data formats, and interfaces may change at any time in the
  future without warning.**

## Installing

```shell
go get -d -u github.com/codahale/kmssig
cd $GOPATH/src/github.com/codahale/kmssig
make install
kms-sig version
```

## Configuring Access to AWS

`kms-sig` requires access to AWS APIs, which means it needs a set of AWS
credentials. It will look for the `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` environment variables, the default credentials
profile (e.g. `~/.aws/credentials`), and finally any instance profile
credentials for systems running on EC2 instances.

In general, if the `aws` command works, `kms-sig` should work as well.

If you have multi-factor authentication enabled for your AWS account
(**and you should**), you may need to provide a token via the
`AWS_SESSION_TOKEN` environment variable.

## Setting Up The Environment

`kms-sig` requires a KMS master key.

You can create a KMS key via the AWS Console or using a recent version
of `aws`. When you've created the key, store its ID (a UUID) in an
environment variable:

```shell
export KMS_KEY_ID="9ed356fb-5f0f-4792-983d-91866faa3705"
```

Next, ensure that all IAM users and roles which are authorized to
**sign** files are granted access to `Encrypt` operations for that key.

Finally, ensure that all IAM users and roles which are authorized to
**verify** signatures are granted access to `Decrypt` operations for
that key.

**The security of `kms-sig` depends entirely on these permissions.**

## Signing Files

To sign a file, run the following:

```shell
kms-sig sign $KMS_KEY_ID README.md README.md.sig
```

This hashes the given file with SHA-512, then sends the hash to KMS to
be encrypted with the given key. The resulting ciphertext is used as the
signature.

## Verifying Signatures

To verify a signature, run the following:

```shell
kms-sig verify README.md README.md.sig
```

This hashes the given file with SHA-512, then sends the signature to KMS
to be decrypted. If KMS returns a plaintext, the plaintext is compared
to the hash.

If they match, `kms-sig` will print the KMS key ID used to create the
signature and will exit with an exit status of `0`.

If they do **not** match, `kms-sig` will print an error and exit with an
exit status of `1`.

## Contexts

KMS supports the notion of an
[Encryption Context](http://docs.aws.amazon.com/kms/latest/developerguide/encrypt-context.html):
semi-structured data used in the encryption of data which is then
required for resulting decryption operations to be successful.

You can specify a context when signing a file:

```shell
kms-sig sign $KMS_KEY_ID README.md README.md.sig --context="hostname=web1.example.com,version=20"
```

All data in the encryption contexts are logged via CloudTrail, which
allows you to track when and where particular files are signed and
verified.

## Implementation Details

A `kms-sig` signature is simply a SHA-512 hash, encrypted with
AES-256-GCM, plus some KMS-specific metadata.

Because GCM is an IND-CCA2 AEAD construction, it provides integrity of
both the ciphertext and the encryption context. If a single bit of
either are modified, KMS will return an error rather than an invalid
plaintext.

## Threat Model

The threat model is defined in terms of what each possible attacker can
achieve. The list is intended to be exhaustive, i.e. if an entity can do
something that is not listed here then that should count as a break of
`kms-sig`.

In broad strokes, the integrity of content signed with `kms-sign` is
predicated on the the confidentiality and integrity of KMS.

### Assumptions

* The user must act reasonably and in their best interest. They must not
  allow unauthorized access to KMS operations.

* The user must run a copy of `kms-sig` which has not been suborned.

* The user's computer must function correctly and not be compromised by
  malware.

* Communications with Amazon have confidentiality and integrity ensured
  by the use of TLS.

* Key Management Service is reasonably secure: its keys will not be
  compromised, its random numbers are unguessable to adversaries, its
  cryptographic algorithms are correct.

* The authentication and access control functionality of KMS is secure.

* AES-256 and GCM's security guarantees are valid.

### Threats From A KMS Compromise

An attacker who suborns KMS can:

* Create forged signatures.
* Deny the ability to verify signatures, either temporarily or
  permanently.

### Threats From Seizure Or Compromise Of The User's Computer

An attacker who physically seizes the user's computer (or compromises
the user's backups) or otherwise compromises it can:

* Recover AWS credentials and pose as the user. If multi-factor
  authentication is not enabled, this would allow the attacker to
  create forged signatures, verify signatures, etc.
