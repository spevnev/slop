# slop

Simple Login Program is a replacement for getty and login.

### Features

- Focus the TTY
- Set command to run on successful login
- Clear screen after failed attempt
- Set title above the prompt
- Predefine a username

## Build & Install

```console
$ make
$ make install
$ make uninstall
```

### systemd

Create a drop-in configuration for chosen getty instance and specify options.
In order for `--focus` to work, the getty service must be enabled.

```ini
# /etc/systemd/system/getty@ttyN.service.d/slop.conf

[Service]
# Empty ExecStart clears the previous value.
ExecStart=
ExecStart=slop -u test_user -t Title -c startx --focus
```
