# crackpkcs12
A multithreaded program to crack PKCS#12 files (p12 and pfx extensions) by Aestu

## What is it?

crackpkcs12 is a tool to audit PKCS#12 files passwords (extension .p12 or .pfx). It's written in C and uses openssl library.

It works on GNU/Linux and other UNIX systems.

His author is aestu and his license is GPLv3+ slightly modified to use openssl library.

## How to compile and install it?

You have to install libssl development library. libssl-dev is the package in Debian like distros and openssl-devel in RedHat like distros.

Afterwards, you can follow the standard process:

```bash
tar -xf crackpkcs12*
cd crackpkcs12*
./configure
make
sudo make install
```

## How to use it?

crackpkcs12 is able to perform two types of attack: Dictionary (no dictionary is provided) or brute force.

Use help message to read the params description:

```bash
crackpkcs12 -h 
```

## Examples

A simple dictionary attack:

```bash
crackpkcs12 -d dictionary.txt certificate.pfx
```

A simple brute force attack:

```bash
crackpkcs12 -b certificate.pfx
```

A combinate attack. When dictionary attack finishes, a brute force attack starts:

```bash
crackpkcs12 -b -d dictionary.txt certificate.pfx
```

A combinate attack. When dictionary attack finishes, a brute force attack starts. Brute force attack uses just lower and upper case letters:

```bash
crackpkcs12 -d dictionary.txt -b -caA certificate.pfx
```

A combinate attack. When dictionary attack finishes, a brute force attack starts. Brute force attack uses just numbers and minimun length of passwords is 5:

```bash
crackpkcs12 -d dictionary.txt -b -cn -m5 certificate.pfx
```
