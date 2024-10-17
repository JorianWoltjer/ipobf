# IP Obfuscator (ipobf)

Obfuscate an IP address by taking advantage of lax parsers allowing hexdecimal and octal encoding, multi-byte integers and IPv6 compatibility.

## Usage

```shell
$ ipobf --help
```

### Example

Below is an example of some addresses that come out of the cloud metadata IP (169.254.169.254).

```shell
$ ipobf 169.254.169.254
169.254.169.254
0xa9.0xfe.0xa9.0xfe
0x000a9.0x000fe.0x000a9.0x000fe
0XA9.0XFE.0XA9.0XFE
...
0251.0376.0251.0376
169.254.43518
0X000A9.0X000FEA9FE
000025177524776
::ffff:a9fe:a9fe
0:0:00:000:0000:FFFF:A9FE:A9FE
::a9fe:a9fe
0:0:0:0:0:0:169.254.169.254
```
