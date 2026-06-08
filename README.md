# ipcalc (Go)

This is a Go rewrite of Krischan Jodies' old `ipcalc` perl script (the one a
lot of people still have kicking around from jodies.de). The original is GPL
and still works fine, but it's perl and dragging a perl interpreter onto every
box just to do subnet math got old, so I ported it to Go. Single static binary,
no runtime deps, drop it on a host and go.

The output is meant to match the original pretty closely - same columns, same
colors, same binary view - so if you've used the perl one your muscle memory
still works. I did add a proper IPv6 mode while I was in there (more on that
below).

> The `perl/` folder is the original script kept around for reference. Ignore
> it, none of it is used by the Go build.

## What it does

You give it an address and (optionaly) a netmask and it prints the network,
broadcast, host range, wildcard mask and the bit-by-bit binary breakdown. Give
it a second netmask and it'll show you the subnets or the supernet for that
transition. Theres also range deaggregation and a network splitter.

```
$ ipcalc 192.168.1.1/24
Address:   192.168.1.1          11000000.10101000.00000001. 00000001
Netmask:   255.255.255.0 = 24   11111111.11111111.11111111. 00000000
Wildcard:  0.0.0.255            00000000.00000000.00000000. 11111111
=>
Network:   192.168.1.0/24       11000000.10101000.00000001. 00000000
HostMin:   192.168.1.1          11000000.10101000.00000001. 00000001
HostMax:   192.168.1.254        11000000.10101000.00000001. 11111110
Broadcast: 192.168.1.255        11000000.10101000.00000001. 11111111
Hosts/Net: 254                   Class C, Private Internet
```

The space in the binary column is the network/host boundary. Bits to the left
are network, bits to the right are host - that's the whole point of the binary
view, it makes the mask boundary obvious.

## Building

You need Go 1.22 or newer.

```
go build -o ipcalc .
```

That gives you a `ipcalc` binary in the current dir. Stick it in your `$PATH`
somewhere. Or if you'd rather let Go do it:

```
go install github.com/JoshFinlayAU/go-ipcalc@latest
```

which drops the binary in `$(go env GOPATH)/bin` (named `go-ipcalc` - rename it
to `ipcalc` if you want, the help text still says ipcalc).

## Usage

```
ipcalc [options] <ADDRESS>[[/]<NETMASK>] [NETMASK]
```

Netmask can be CIDR (`/24`), dotted decimal (`255.255.255.0`), an inverse /
wildcard mask (`0.0.0.255`), or hex (`ffffff00` / `0xffffff00`). If you leave
the netmask off it defaults to /24 like the original did.

### Options

```
 -n --nocolor   don't emit ANSI colour codes
 -c --color     force ANSI colours (on by default when stdout is a tty)
 -b --nobinary  drop the binary column
    --class     just print the bit-count-mask of the address and exit
 -h --html      HTML output  (carried over from the original, still unfinished)
 -v --version   print version
 -s --split n1 n2 n3 ...   split the network to fit subnets of those sizes
 -r --range     deaggregate an address range
    --help      the longer help blurb
```

Colours auto-disable under dumb terminals and inside Emacs (it checks `$TERM`
and `$INSIDE_EMACS`), so you shouldn't get escape-code garbage in a pipe or a
build log.

### A few examples

```
ipcalc 192.168.0.1/24
ipcalc 192.168.0.1/255.255.128.0
ipcalc 192.168.0.1 255.255.128.0 255.255.192.0   # subnets on the transition
ipcalc 192.168.0.1 0.0.63.255                     # wildcard mask input
ipcalc 10.0.0.0/24 --split 50 20 10               # carve out vlsm subnets
ipcalc 192.168.0.0 - 192.168.5.255                # deaggregate a range -> cidrs
```

Two masks where the second is *longer* gives you the subnets after the
transition; second mask *shorter* gives you the supernet.

## IPv6

IPv6 is detected automaticaly from the address (if it's got colons in it, it's
v6) so there's no flag to remember. It gives you a fuller breakdown than the v4
side does:

```
$ ipcalc 2001:db8::1/64
[ 2001:db8::1/64 ]

Address:   2001:db8::1            0010000000000001:0000110110111000: ...
Full:      2001:0db8:0000:0000:0000:0000:0000:0001
Netmask:   ffff:ffff:ffff:ffff:: = 64
...
Hosts/Net: 18446744073709551616 (2^64)
Subnets/64: ...
Type:      Documentation (2001:db8::/32)
arpa:      1.0.0.0.0.0.0.0...8.b.d.0.1.0.0.2.ip6.arpa.
```

You get the expanded (un-shortened) form, host count, the /64 subnet count when
the prefix is shorter than 64, the address *type* looked up against the IANA
special-purpose registry (ULA, link-local, documentation, 6to4, NAT64, teredo,
the lot), and the `ip6.arpa` reverse pointer. Subnet/supernet transitions and
`--split` work for v6 as well.

Addresses are printed compressed per RFC 5952 (longest zero run collapses to
`::`, single zero fields are not collapsed).

## Notes on the port

A few things worth knowing if you go poking at the code:

- It's a single file (`main.go`) and uses **only the standard library**. No
  third party packages, nothing to vendor.
- IPv4 math is done in `int64` and masked back to 32 bits where the perl used
  its `& $thirtytwobits` trick. IPv6 uses `math/big` to get the 128-bit
  arithmetic that perl was getting from `use bignum`.
- The subnet listing stops at 1000 entries on purpose (same as the original) so
  a `/8 -> /30` doesn't try to print the heat death of the universe.
- Output is kept byte-for-byte close to the perl where I could manage it. If
  you find a place where it diverges and it's not obviously a bug fix, that's
  probably a bug - open an issue.

The HTML mode (`-h`) is ported but was never finished in the original either,
so consider it best-effort. Plain text and colour are the paths that actually
get used.

## License

GPL v2 or later, same as the upstream perl script. Original ipcalc is
Copyright (C) Krischan Jodies 2000-2017, http://jodies.de/ipcalc - all credit
for the design and the math goes to him, this is just a port. See `perl/license`
for the full text.
