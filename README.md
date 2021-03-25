# mailparse

Mailparse is an utility to parse postfix log files and display the path of a
given message in an easy-to-use manner.

## Usage

Search for a message ID in a given log file:
```
$ mailparse [message-id] /var/log/prod/mail/mail.log
```

Search for a message-ID across multiple log files:
```
$ mailparse [message-id] /var/log/prod/mail/mail-*.log
```

Search for a message-ID across all mail-related log files (warning: this is
usually slow):
```
$ mailparse [message-id]
```

## Deployment

`mailparse` can simply be build with `cargo build --release` and then used from
`target/release/mailparse`.

Unfortunately, current debian's rustc is too old for that, and it means that we
have to build it another way.

The recommended way is to build a musl-static version of mailparse on a machine
that has `nix` installed, by running `./build-static.sh` from the root of the
repository. This generates a `result/bin/mailparse` file, that can then be
copied to the relevant server and used from there.

Hopefully this will no longer be required after a few upgrade cycles.
