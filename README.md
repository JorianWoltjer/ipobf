# IP Obfuscator (ipobf)

Obfuscate an IP address by taking advantage of lax parsers allowing hexdecimal and octal encoding, multi-byte integers and IPv6 compatibility.

## Installation

```bash
cargo install ipobf
```

Or **download** and **extract** a pre-compiled binary from the [Releases](https://github.com/JorianWoltjer/ipobf/releases) page. 

Alternatively, **build from source** ([requires Rust](https://www.rust-lang.org/tools/install)):

```bash
git clone https://github.com/JorianWoltjer/ipobf.git && cd ipobf
cargo install --path .
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
a9fea9fe.nip.io
a9fea9fe.01010101.rbndr.us
169-254-169-254.redir.jtw.sh
```

## Usage

```shell
$ ipobf --help
A simple CLI to obfuscate IP addresses

Usage: ipobf [OPTIONS] <HOST>

Arguments:
  <HOST>  The IP address to obfuscate. May also be a hostname or any of "cloud|meta|metadata" to use 169.254.169.254

Options:
  -p, --padding <PADDING>  The amount of 0-padding to use [default: 3]
  -n, --no-aliases         Disable adding few extra aliases for localhost (eg. 0.0.0.0, 127.1.2.3) and cloud (eg. [fd00:ec2::254])
  -o, --output <OUTPUT>    Output file
  -a, --output-append      Append to the output file
  -b, --brackets           Add brackets to IPv6 addresses
  -h, --help               Print help
```
