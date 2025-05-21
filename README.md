# fscryptrs :: Encrypted Filesystem for Linux

This repository contains the source code to a FUSE-based protected filesystem
for Linux. It is an overlay filesystem that works similarly as EncFS, or
gocryptfs.

#### Minimum Supported Rust Version

Rust **1.86** or higher

# Getting started
To download and build the filesystem use:
```
$ git clone https://github.com/imnotfromthisworld/fscryptrs.git
$ cd fscryptrs
$ cargo build --release
```

# Running

Before being able to mount the filesystem, it requires an initialized encrypted
directory.

To initialize directory at `<encrypted_root>` use:
```
$ ./target/release/fscryptrs init --cipher aes256-gcm --digest blake2 --mode block <encrypted_root>
```

To mount the filesystem at `<mount>` directory, with the encrypted data residing
in `<encrypted_root>` use:
```
$ ./target/release/fscryptrs mount <encrypted_root> <mount>
```
Most commands will request a password from the user.

> [!CAUTION]
> The password can be specified at command line with `--password` flag. In that
> case, the filesystem will not prompt the user for password. Specifying
> password at command line may have unwanted security implications such as
> password leakage.

> [!IMPORTANT]
> The filesystem requires `CAP_SYS_CHROOT` capability which can be set using 
> ```
> # setcap cap_sys_chroot+ep ./target/release/fstest
> ```
> Upon mounting the filesystem, it changes root to specified `encrypted_root`
> directory and drops the capability.

The filesystem contains help which can be shown with the `help` flag.
Some examples:
```
$ fscryptrs help
```
Shows main help describing possible subcommands.

```
$ fscryptrs help <subcommand> 
```
Shows help of the specified subcommand:
```
$ fscryptrs help init
```
Shows help of `init` subcommand, explains possible flags and their respective
values.



# Benchmarks
The `benchmarks` directory contains scripts and results used for benchmarking
the filesystem. The visualisations are created using jupyter notebooks.


# Testing
Before being able to run tests, test files need to be generated using
```
$ ./tests/gen_tests.sh
```

To run tests, use:
```
$ cargo test
```
To cleanup the generated test files, use :

```
$ ./tests/cleanup.sh
```

