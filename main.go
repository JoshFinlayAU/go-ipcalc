// IPv4/IPv6 Calculator
//
// A Go port of Krischan Jodies' "ipcalc" Perl script
// (Copyright (C) Krischan Jodies 2000-2004, GPL v2 or later,
//
//	http://jodies.de/ipcalc).
//
// This port uses only the Go standard library. IPv4 math is done with
// int64 (masked to 32 bits where the original used "& $thirtytwobits"),
// and IPv6 math uses math/big to emulate Perl's "use bignum" 128-bit
// arithmetic.
package main

import (
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const version = "0.5"

// natural-class bit counts, indexed by class number 1..5 (index 0 unused).
var classArr = []int{0, 8, 16, 24, 4, 5, 5}

const mask32 int64 = 0xFFFFFFFF // for masking bitwise-not on a 64-bit arch

// ---- colors / output mode ---------------------------------------------

var (
	quadsColor = "\033[34m"        // dotted quads, blue
	normlColor = "\033[m"          // normal, black
	binryColor = "\033[33m"        // binary, yellow
	maskColor  = "\033[31m"        // netmask, red
	classColor = "\033[35m"        // classbits, magenta
	subntColor = "\033[0m\033[32m" // subnet bits, green
	errorColor = "\033[31m"
	sfont      = ""
	breakStr   = "\n"
)

var (
	colorOld    = ""
	colorActual = ""
)

// ---- options ----------------------------------------------------------

var (
	optText           = true
	optHTML           = false
	optColor          = false
	optPrintBits      = true
	optPrintOnlyClass = false
	optSplit          = false
	optDeaggregate    = false
	optVersion        = false
	optHelp           = false
	optSplitSizes     []int
	errMsg            = ""
	ipv6              = false
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	argv := getopts(os.Args[1:])

	if optHelp {
		help()
		return
	}
	if optVersion {
		fmt.Printf("%s\n", version)
		return
	}

	if !optColor {
		quadsColor = ""
		normlColor = ""
		binryColor = ""
		maskColor = ""
		classColor = ""
		subntColor = ""
		sfont = ""
	}

	if optHTML {
		quadsColor = `<font color="#0000ff">`
		normlColor = `<font color="#000000">`
		binryColor = `<font color="#909090">`
		maskColor = `<font color="#ff0000">`
		classColor = `<font color="#009900">`
		subntColor = `<font color="#663366">`
		sfont = "</font>"
		breakStr = "<br>"
		fmt.Print(`<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta HTTP-EQUIV="content-type" CONTENT="text/html; charset=UTF-8">
<title>Bla</title>
</head>
<body>
`)
		fmt.Printf("<!-- Version %s -->\n", version)
	}

	address := int64(-1)
	var addressV6 *big.Int
	address2 := int64(-1)
	var address2V6 *big.Int

	// base address
	if len(argv) > 0 {
		address, addressV6 = argton(argv[0], false)
	}
	if address == -1 && addressV6 == nil {
		arg0 := ""
		if len(argv) > 0 {
			arg0 = argv[0]
		}
		errMsg += "INVALID ADDRESS: " + arg0 + "\n"
		address, addressV6 = argton("192.168.1.1", false)
	}

	if optPrintOnlyClass {
		fmt.Print(getclass(address, true))
		return
	}

	// if deaggregate, get last address
	if optDeaggregate {
		if len(argv) > 1 {
			address2, address2V6 = argton(argv[1], false)
		}
		if ipv6 {
			if address2V6 == nil {
				arg1 := ""
				if len(argv) > 1 {
					arg1 = argv[1]
				}
				errMsg += "INVALID ADDRESS2: " + arg1 + "\n"
				address2V6 = new(big.Int).Set(addressV6)
			}
			if errMsg != "" {
				fmt.Printf("%s\n", errMsg)
			}
			fmt.Printf("deaggregate %s - %s\n", ntoip6(addressV6), ntoip6(address2V6))
			deaggregate6(addressV6, address2V6)
			return
		}
		if address2 == -1 {
			arg1 := ""
			if len(argv) > 1 {
				arg1 = argv[1]
			}
			errMsg += "INVALID ADDRESS2: " + arg1 + "\n"
			address2, _ = argton("192.168.1.1", false)
		}
		if errMsg != "" {
			fmt.Printf("%s\n", errMsg)
		}
		fmt.Printf("deaggregate %s - %s\n", ntoa(address), ntoa(address2))
		deaggregate(address, address2)
		return
	}

	// get netmasks
	var mask1, mask2 int64
	var mask1v6, mask2v6 int // ipv6 prefix lengths
	if ipv6 {
		if len(argv) > 1 {
			m := checkMask6(argv[1])
			if m == -1 {
				fmt.Print("INVALID MASK1\n\n")
				return
			}
			mask1v6 = m
		} else {
			mask1v6 = 64
		}
		if len(argv) > 2 {
			m := checkMask6(argv[2])
			if m == -1 {
				fmt.Print("INVALID MASK2\n\n")
				return
			}
			mask2v6 = m
		} else {
			mask2v6 = mask1v6
		}
	} else {
		mask1 = -1
		mask2 = -1
		if len(argv) > 1 {
			mask1, _ = argton(argv[1], true)
		} else {
			// natural mask (defaults to /24, like the original)
			mask1, _ = argton("24", true)
		}
		if mask1 == -1 {
			arg1 := ""
			if len(argv) > 1 {
				arg1 = argv[1]
			}
			errMsg += "INVALID MASK1:   " + arg1 + "\n"
			mask1, _ = argton("24", true)
		}

		if len(argv) > 2 {
			mask2, _ = argton(argv[2], true)
		} else {
			mask2 = mask1
		}
		if mask2 == -1 {
			arg2 := ""
			if len(argv) > 2 {
				arg2 = argv[2]
			}
			errMsg += "INVALID MASK2:   " + arg2 + "\n"
			mask2, _ = argton("24", true)
		}
	}

	if errMsg != "" {
		if optColor {
			fmt.Print(setColor(errorColor))
		}
		fmt.Printf("%s\n", errMsg)
		fmt.Print(setColor(normlColor))
		return
	}

	if ipv6 {
		ipcalc6(addressV6, address2V6, mask1v6, mask2v6)
		return
	}

	html(`<table border="0" cellspacing="0" cellpadding="0">`)
	html("\n")
	printline("Address", address, mask1, mask1, true)
	printline("Netmask", mask1, mask1, mask1, false)
	printline("Wildcard", (^mask1)&mask32, mask1, mask1, false)
	html("<tr>\n")
	html(`<td colspan="3"><tt>`)
	fmt.Print("=>")
	html("</tt></td>\n")
	html("</tr>\n")
	fmt.Print("\n")

	network := address & mask1
	printnet(network, mask1, mask1)
	html("</table>\n")

	if optSplit {
		splitNetwork(network, mask1, mask2, optSplitSizes)
		return
	}
	if mask1 < mask2 {
		fmt.Printf("Subnets after transition from /%d", ntobitcountmask(mask1))
		fmt.Printf(" to /%d\n\n", ntobitcountmask(mask2))
		subnets(network, mask1, mask2)
	}
	if mask1 > mask2 {
		fmt.Print("Supernet\n\n")
		supernet(network, mask1, mask2)
		if optHTML {
			html("</table>\n")
		}
	}
	if optHTML {
		fmt.Print(`    <p>
      <a href="http://validator.w3.org/check/referer"><img border="0"
          src="http://www.w3.org/Icons/valid-html401"
          alt="Valid HTML 4.01!" height="31" width="88"></a>
    </p>
`)
	}
}

// ---------------------------------------------------------------------

func supernet(network, mask1, mask2 int64) {
	network = network & mask2
	printline("Netmask", mask2, mask2, mask1, true)
	printline("Wildcard", (^mask2)&mask32, mask2, mask1, false)
	fmt.Print("\n")
	printnet(network, mask2, mask1)
}

func subnets(network, mask1, mask2 int64) {
	bc1 := ntobitcountmask(mask1)
	bc2 := ntobitcountmask(mask2)

	html(`<table border="0" cellspacing="0" cellpadding="0">`)
	html("\n")
	printline("Netmask", mask2, mask2, mask1, true)
	printline("Wildcard", (^mask2)&mask32, mask2, mask1, false)
	html("</table>\n")

	fmt.Print("\n")

	count := int64(1) << uint(bc2-bc1)
	var subnet int64
	for subnet = 0; subnet < count; subnet++ {
		net := network | (subnet << uint(32-bc2))
		fmt.Printf(" %d.\n", subnet+1)
		html(`<table border="0" cellspacing="0" cellpadding="0">`)
		html("\n")
		printnet(net, mask2, mask1)
		html("</table>\n")
		if subnet >= 1000 {
			fmt.Printf("... stopped at 1000 subnets ...%s", breakStr)
			break
		}
	}
	subnet = int64(1) << uint(bc2-bc1)
	hostn := (network | ((^mask2) & mask32)) - network - 1
	if hostn > -1 {
		fmt.Printf("\nSubnets:   %s%d", quadsColor, subnet)
		html("</font>")
		fmt.Printf("%s%s", normlColor, breakStr)
		html("</font>")
	}
	if hostn < 1 {
		hostn = 1
	}
	fmt.Printf("Hosts:     %s%d", quadsColor, hostn*subnet)
	html("</font>")
	fmt.Printf("%s%s", normlColor, breakStr)
	html("</font>")
}

func getclass(network int64, numeric bool) string {
	class := 1
	for (network & (1 << uint(32-class))) == (1 << uint(32-class)) {
		class++
		if class > 5 {
			return "invalid"
		}
	}
	if numeric {
		return strconv.Itoa(classArr[class])
	}
	return string(rune(class + 64))
}

func printnet(network, mask1, mask2 int64) {
	broadcast := network | ((^mask1) & mask32)

	hmin := network + 1
	hmax := broadcast - 1
	hostn := hmax - hmin + 1
	mask := ntobitcountmask(mask1)
	if mask == 31 {
		hmax = broadcast
		hmin = network
		hostn = 2
	}
	if mask == 32 {
		hostn = 1
	}

	if mask == 32 {
		printline("Hostroute", network, mask1, mask2, true)
	} else {
		printline("Network", network, mask1, mask2, true)
		printline("HostMin", hmin, mask1, mask2, false)
		printline("HostMax", hmax, mask1, mask2, false)
		if mask < 31 {
			printline("Broadcast", broadcast, mask1, mask2, false)
		}
	}

	html("<tr>\n")
	html(`<td valign="top"><tt>`)
	fmt.Print(setColor(normlColor))
	fmt.Print("Hosts/Net: ")
	html("</font></tt></td>\n")
	html(`<td valign="top"><tt>`)
	fmt.Print(setColor(quadsColor))
	fmt.Printf("%-22s", strconv.FormatInt(hostn, 10))
	html("</font></tt></td>\n")
	html("<td>")
	if optHTML {
		fmt.Print(wrapHTML(30, getDescription(network, mask1)))
	} else {
		fmt.Print(getDescription(network, mask1))
	}
	html("</font></td>\n")
	html("</tr>\n")
	html("\n")
	text("\n")
	text("\n")
}

func getDescription(network, mask int64) string {
	var description []string
	// class
	if optColor || optHTML {
		field := setColor(classColor) + "Class " + getclass(network, false)
		if optHTML {
			field += "</font>"
		}
		field += setColor(normlColor)
		description = append(description, field)
	} else {
		description = append(description, "Class "+getclass(network, false))
	}
	// netblock
	nb := netblock(network, mask)
	if nb != "" {
		parts := strings.SplitN(nb, ",", 2)
		netblockTxt := parts[0]
		netblockURL := ""
		if len(parts) > 1 {
			netblockURL = parts[1]
		}
		if optHTML {
			netblockTxt = `<a href="` + netblockURL + `">` + netblockTxt + "</a>"
		}
		description = append(description, netblockTxt)
	}
	// /31
	if ntobitcountmask(mask) == 31 {
		if optHTML {
			description = append(description, `<a href="http://www.ietf.org/rfc/rfc3021.txt">PtP Link</a>`)
		} else {
			description = append(description, "PtP Link RFC 3021")
		}
	}
	return strings.Join(description, ", ")
}

func printline(label string, address, mask1arg, mask2arg int64, htmlFillup bool) {
	mask1 := ntobitcountmask(mask1arg)
	mask2 := ntobitcountmask(mask2arg)
	line := ""
	newbitcolorOn := false
	additionalInfo := ""
	classbitcolorOn := false

	if label == "Netmask" {
		additionalInfo = fmt.Sprintf(" = %d", mask1)
	}
	if label == "Network" {
		classbitcolorOn = true
		additionalInfo = fmt.Sprintf("/%d", mask1)
	}
	if label == "Hostroute" && mask1 == 32 {
		classbitcolorOn = true
	}

	html("<tr>\n")
	html("<td><tt>")
	// label
	fmt.Print(setColor(normlColor))
	if optHTML && htmlFillup {
		fmt.Printf("%s:", label)
		fmt.Print(strings.Repeat("&nbsp;", 11-len(label)))
	} else {
		fmt.Printf("%-11s", label+":")
	}
	html("</font></tt></td>\n")
	// address
	html("<td><tt>")
	fmt.Print(setColor(quadsColor))
	secondField := ntoa(address) + additionalInfo
	if optHTML && htmlFillup {
		fmt.Print(secondField)
		fmt.Print(strings.Repeat("&nbsp;", 21-len(secondField)))
	} else {
		fmt.Printf("%-21s", secondField)
	}
	html("</font></tt></td>\n")

	if optPrintBits {
		html("<td><tt>")
		bitColor := setColor(binryColor)
		if label == "Netmask" {
			bitColor = setColor(maskColor)
		}

		if classbitcolorOn {
			line += setColor(classColor)
		} else {
			line += setColor(bitColor)
		}
		for i := 1; i < 33; i++ {
			bit := 0
			if (address & (1 << uint(32-i))) == (1 << uint(32-i)) {
				bit = 1
			}
			line += strconv.Itoa(bit)
			if classbitcolorOn && bit == 0 {
				classbitcolorOn = false
				if newbitcolorOn {
					line += setColor(subntColor)
				} else {
					line += setColor(bitColor)
				}
			}
			if i%8 == 0 && i < 32 {
				line += setColor(normlColor) + "."
				line += setColor("oldcolor")
			}
			if i == mask1 {
				line += " "
			}
			if (i == mask1 || i == mask2) && mask1 != mask2 {
				if newbitcolorOn {
					newbitcolorOn = false
					if !classbitcolorOn {
						line += setColor(bitColor)
					}
				} else {
					newbitcolorOn = true
					if !classbitcolorOn {
						line += setColor(subntColor)
					}
				}
			}
		}
		line += setColor(normlColor)
		fmt.Print(line)
		html("</tt></font></td>\n")
	}
	html("</tr>\n")
	html("\n")
	text("\n")
}

func text(s string) {
	if optText {
		fmt.Print(s)
	}
}

func html(s string) {
	if optHTML {
		fmt.Print(s)
	}
}

func setColor(newColor string) string {
	if newColor == "oldcolor" {
		newColor = colorOld
	}
	colorOld = colorActual
	colorActual = newColor
	return newColor
}

func splitNetwork(network, mask1, mask2 int64, sizes []int) {
	firstAddress := network
	broadcast := network | ((^mask1) & mask32)

	type entry struct {
		size int64
		nr   int
	}
	var netList []entry
	needed := int64(0)
	for i, s := range sizes {
		neededSize := round2powerof2(int64(s) + 2)
		netList = append(netList, entry{neededSize, i})
		needed += neededSize
	}
	// sort descending by size
	sort.SliceStable(netList, func(a, b int) bool {
		return netList[a].size > netList[b].size
	})

	net := make([]int64, len(sizes))
	maskBits := make([]int, len(sizes))
	running := network
	for _, e := range netList {
		net[e.nr] = running
		maskBits[e.nr] = 32 - log2(e.size)
		running += e.size
	}

	for i := 0; i < len(sizes); i++ {
		fmt.Printf("%d. Requested size: %d hosts\n", i+1, sizes[i])
		printline("Netmask", bitcountmaskton(maskBits[i]), bitcountmaskton(maskBits[i]), mask2, false)
		printnet(net[i], bitcountmaskton(maskBits[i]), mask2)
	}

	usedMask := 32 - log2(round2powerof2(needed))
	if usedMask < ntobitcountmask(mask1) {
		fmt.Print("Network is too small\n")
	}
	fmt.Printf("Needed size:  %d addresses.\n", needed)
	fmt.Printf("Used network: %s/%d\n", ntoa(firstAddress), usedMask)
	fmt.Print("Unused:\n")
	deaggregate(running, broadcast)
}

func round2powerof2(x int64) int64 {
	i := uint(0)
	for x > (1 << i) {
		i++
	}
	return 1 << i
}

// log2 of a power-of-two value.
func log2(x int64) int {
	if x <= 0 {
		return 0
	}
	return bits.TrailingZeros64(uint64(x))
}

// Deaggregate an address range (dotted-quad start, dotted-quad end).
func deaggregate(start, end int64) {
	base := start
	for base <= end {
		step := 0
		for step < 32 && (base|(1<<uint(step))) != base {
			if (base | ((mask32) >> uint(31-step))) > end {
				break
			}
			step++
		}
		fmt.Printf("%s/%d\n", ntoa(base), 32-step)
		base += 1 << uint(step)
	}
}

// ---- option parsing ---------------------------------------------------

func getopts(argv []string) []string {
	// opt_color defaults to 1 when connected to a terminal
	if fi, err := os.Stdout.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		optColor = true
	}
	// Under Emacs / dumb terminals, do not use colors by default.
	term := os.Getenv("TERM")
	if term == "" || strings.Contains(strings.ToLower(term), "dumb") || os.Getenv("INSIDE_EMACS") != "" {
		optColor = false
	}

	var tmp []string
	nrOpts := 0

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if strings.HasPrefix(a, "--") {
			nrOpts += readOpt("--", []string{a[2:]}, argv, &i)
		} else if strings.HasPrefix(a, "-") && len(a) > 1 {
			nrOpts += readOpt("-", strings.Split(a[1:], ""), argv, &i)
		} else {
			tmp = append(tmp, a)
		}
	}

	// extract base address and netmasks and ranges
	var arguments []string
	reCIDR := regexp.MustCompile(`^(.+?)/(.+)$`)
	reTrailSlash := regexp.MustCompile(`^(.+)/$`)
	reRange := regexp.MustCompile(`^(.+)-(.+)$`)
	for _, t := range tmp {
		switch {
		case reTrailSlash.MatchString(t):
			m := reTrailSlash.FindStringSubmatch(t)
			arguments = append(arguments, m[1])
		case reCIDR.MatchString(t):
			m := reCIDR.FindStringSubmatch(t)
			arguments = append(arguments, m[1], m[2])
		case t == "-":
			optDeaggregate = true
		case reRange.MatchString(t):
			m := reRange.FindStringSubmatch(t)
			arguments = append(arguments, m[1], m[2])
			optDeaggregate = true
		default:
			arguments = append(arguments, t)
		}
	}
	if len(arguments) == 3 && arguments[1] == "-" {
		arguments = []string{arguments[0], arguments[2]}
		optDeaggregate = true
	}

	// workaround for -h
	if optHTML && nrOpts == 1 && len(arguments) == 0 {
		optHelp = true
	}

	if errMsg != "" {
		fmt.Print(errMsg)
		os.Exit(0)
	}
	return arguments
}

var reNumeric = regexp.MustCompile(`^\d+$`)

func readOpt(prefix string, opts []string, argv []string, i *int) int {
	optsRead := 0
	for _, opt := range opts {
		optsRead++
		switch {
		case opt == "h" || opt == "html":
			optHTML = true
			optText = false
		case opt == "help":
			optHelp = true
		case opt == "c" || opt == "color":
			optColor = true
		case opt == "n" || opt == "nocolor":
			optColor = false
		case opt == "v" || opt == "version":
			optVersion = true
		case opt == "b" || opt == "nobinary":
			optPrintBits = false
		case opt == "class":
			optPrintOnlyClass = true
		case opt == "r" || opt == "range":
			optDeaggregate = true
		case opt == "s" || opt == "split":
			optSplit = true
			for *i+1 < len(argv) && reNumeric.MatchString(argv[*i+1]) {
				*i++
				n, _ := strconv.Atoi(argv[*i])
				optSplitSizes = append(optSplitSizes, n)
			}
			if len(optSplitSizes) == 0 {
				errMsg += "Argument for " + prefix + opt + " is missing or invalid \n"
			}
		default:
			errMsg += "Unknown option: " + prefix + opt + "\n"
			optsRead--
		}
	}
	return optsRead
}

// ---- HTML wrapping ----------------------------------------------------

func wrapHTML(width int, str string) string {
	runes := []rune(str)
	n := len(runes)
	last := n - 1 // mirrors Perl $#str
	var result strings.Builder
	currentPos := 0
	start := 0
	lastPos := 0

	stripTags := regexp.MustCompile(`<.+?>`)

	for currentPos < last {
		// find next blank
		for currentPos < last && runes[currentPos] != ' ' {
			if runes[currentPos] == '<' {
				currentPos++
				for currentPos < n && runes[currentPos] != '>' {
					currentPos++
				}
			}
			currentPos++
		}
		line := substr(runes, start, currentPos-start)
		stripped := stripTags.ReplaceAllString(line, "")
		if len(stripped) <= width {
			lastPos = currentPos
			currentPos++
			continue
		}
		if lastPos != start {
			currentPos = lastPos
		}
		line = substr(runes, start, currentPos-start)
		currentPos++
		start = currentPos
		lastPos = start
		if currentPos < last {
			result.WriteString(line + "<br>")
		}
	}
	result.WriteString(substr(runes, start, currentPos-start))
	return result.String()
}

func substr(runes []rune, start, length int) string {
	if start < 0 {
		start = 0
	}
	if start > len(runes) {
		return ""
	}
	end := start + length
	if end > len(runes) {
		end = len(runes)
	}
	if end < start {
		end = start
	}
	return string(runes[start:end])
}

// ---- netblock ---------------------------------------------------------

// netblock returns "description,url", "In Part description,url", or "".
func netblock(mynetworkStart, mymask int64) string {
	mynetworkEnd := mynetworkStart | ((^mymask) & mask32)
	// ordered so output is deterministic
	type nb struct {
		cidr string
		desc string
	}
	netblocks := []nb{
		{"192.168.0.0/16", "Private Internet,http://www.ietf.org/rfc/rfc1918.txt"},
		{"172.16.0.0/12", "Private Internet,http://www.ietf.org/rfc/rfc1918.txt"},
		{"10.0.0.0/8", "Private Internet,http://www.ietf.org/rfc/rfc1918.txt"},
		{"169.254.0.0/16", "APIPA,http://www.ietf.org/rfc/rfc3330.txt"},
		{"127.0.0.0/8", "Loopback,http://www.ietf.org/rfc/rfc1700.txt"},
		{"224.0.0.0/4", "Multicast,http://www.ietf.org/rfc/rfc3171.txt"},
	}
	for _, b := range netblocks {
		match := 0
		parts := strings.SplitN(b.cidr, "/", 2)
		networkStr := parts[0]
		maskBits, _ := strconv.Atoi(parts[1])
		start, _ := argton(networkStr, false)
		end := start + (1 << uint(32-maskBits)) - 1
		if mynetworkStart >= start && mynetworkStart <= end {
			match++
		}
		if mynetworkEnd >= start && mynetworkEnd <= end {
			match++
		}
		if start > mynetworkStart && end < mynetworkEnd {
			match = 1
		}
		if match == 1 {
			return "In Part " + b.desc
		}
		if match == 2 {
			return b.desc
		}
	}
	return ""
}

// ---- IPv6 -------------------------------------------------------------

// all128 is 2^128 - 1, the full 128-bit mask.
var all128 = func() *big.Int {
	x := big.NewInt(1)
	x.Lsh(x, 128)
	return x.Sub(x, big.NewInt(1))
}()

// pow2 returns 2^n as a big.Int.
func pow2(n int) *big.Int {
	x := big.NewInt(1)
	return x.Lsh(x, uint(n))
}

// round2powerof2big returns the smallest power of two >= x (>= 1).
func round2powerof2big(x *big.Int) *big.Int {
	if x.Sign() <= 0 {
		return big.NewInt(1)
	}
	bl := x.BitLen()
	p := pow2(bl - 1)
	if p.Cmp(x) == 0 {
		return p
	}
	return pow2(bl)
}

// log2big returns the exponent of a power-of-two value.
func log2big(x *big.Int) int {
	if x.Sign() <= 0 {
		return 0
	}
	return x.BitLen() - 1
}

// deaggregate6 splits an arbitrary IPv6 address range into CIDR prefixes
// (the 128-bit analogue of deaggregate).
func deaggregate6(start, end *big.Int) {
	base := new(big.Int).Set(start)
	for base.Cmp(end) <= 0 {
		step := 0
		for step < 128 && base.Bit(step) == 0 {
			// candidate block of 2^(step+1) addresses ending at base | low(step+1) ones
			lowmask := new(big.Int).Rsh(all128, uint(127-step))
			cand := new(big.Int).Or(base, lowmask)
			if cand.Cmp(end) > 0 {
				break
			}
			step++
		}
		fmt.Printf("%s/%d\n", ntoip6(base), 128-step)
		base.Add(base, pow2(step))
	}
}

// splitNetwork6 carves an IPv6 prefix into subnets sized to hold the requested
// address counts (the 128-bit analogue of splitNetwork). Unlike IPv4 there is
// no network/broadcast reservation, so the sizes are taken as-is.
func splitNetwork6(network *big.Int, mask1 int, sizes []int) {
	firstAddress := new(big.Int).Set(network)
	broadcast := new(big.Int).Or(network, new(big.Int).Xor(prefixlenton(mask1), all128))

	type entry struct {
		size *big.Int
		nr   int
	}
	var netList []entry
	needed := big.NewInt(0)
	for i, s := range sizes {
		neededSize := round2powerof2big(big.NewInt(int64(s)))
		netList = append(netList, entry{neededSize, i})
		needed.Add(needed, neededSize)
	}
	sort.SliceStable(netList, func(a, b int) bool {
		return netList[a].size.Cmp(netList[b].size) > 0
	})

	net := make([]*big.Int, len(sizes))
	maskBits := make([]int, len(sizes))
	running := new(big.Int).Set(network)
	for _, e := range netList {
		net[e.nr] = new(big.Int).Set(running)
		maskBits[e.nr] = 128 - log2big(e.size)
		running.Add(running, e.size)
	}

	for i := 0; i < len(sizes); i++ {
		fmt.Printf("%d. Requested size: %d addresses\n", i+1, sizes[i])
		printline6("Netmask", prefixlenton(maskBits[i]), fmt.Sprintf(" = %d", maskBits[i]), maskBits[i], mask1, true)
		netBlock6(net[i], maskBits[i], mask1)
		fmt.Print("\n")
	}

	usedMask := 128 - log2big(round2powerof2big(needed))
	if usedMask < mask1 {
		fmt.Print("Network is too small\n")
	}
	fmt.Printf("Needed size:  %s addresses.\n", needed.String())
	fmt.Printf("Used network: %s/%d\n", ntoip6(firstAddress), usedMask)
	fmt.Print("Unused:\n")
	deaggregate6(running, broadcast)
}

// ntoexp6 returns the fully expanded address (8 groups of 4 hex digits).
func ntoexp6(n *big.Int) string {
	parts := make([]string, 8)
	mask16 := big.NewInt(0xffff)
	for idx, i := 0, 7; i >= 0; i, idx = i-1, idx+1 {
		s := new(big.Int).Rsh(n, uint(i*16))
		s.And(s, mask16)
		parts[idx] = fmt.Sprintf("%04x", s)
	}
	return strings.Join(parts, ":")
}

// ptr6 returns the reverse-DNS (ip6.arpa) name for an address.
func ptr6(n *big.Int) string {
	hex := strings.ReplaceAll(ntoexp6(n), ":", "")
	var b strings.Builder
	for i := len(hex) - 1; i >= 0; i-- {
		b.WriteByte(hex[i])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa.")
	return b.String()
}

// in6 reports whether n falls within base/plen.
func in6(n *big.Int, base string, plen int) bool {
	b := ip6ton(base)
	if b == nil {
		return false
	}
	m := prefixlenton(plen)
	return new(big.Int).And(n, m).Cmp(new(big.Int).And(b, m)) == 0
}

var scopeNames = map[int64]string{
	0: "reserved", 1: "interface-local", 2: "link-local", 3: "realm-local",
	4: "admin-local", 5: "site-local", 8: "organization-local", 14: "global",
	15: "reserved",
}

func multicastType(n *big.Int) string {
	scope := new(big.Int).Rsh(n, 112).Int64() & 0xf
	name, ok := scopeNames[scope]
	if !ok {
		name = "unassigned"
	}
	return fmt.Sprintf("Multicast (ff00::/8, scope: %s)", name)
}

// addrType6 classifies an IPv6 address per the IANA special-purpose registry.
func addrType6(n *big.Int) string {
	if n.Sign() == 0 {
		return "Unspecified (::/128)"
	}
	if n.Cmp(big.NewInt(1)) == 0 {
		return "Loopback (::1/128)"
	}
	type rec struct {
		base string
		plen int
		name string
	}
	recs := []rec{
		{"::ffff:0:0", 96, "IPv4-Mapped"},
		{"::", 96, "IPv4-Compatible (deprecated)"},
		{"64:ff9b::", 96, "NAT64 Well-Known"},
		{"64:ff9b:1::", 48, "NAT64 Local-Use"},
		{"100::", 64, "Discard-Only"},
		{"2001:db8::", 32, "Documentation"},
		{"2001::", 32, "Teredo"},
		{"2001:20::", 28, "ORCHIDv2"},
		{"2001::", 23, "IETF Protocol Assignments"},
		{"2002::", 16, "6to4"},
		{"3fff::", 20, "Documentation"},
		{"5f00::", 16, "SRv6 SIDs"},
		{"fc00::", 7, "Unique Local (ULA)"},
		{"fe80::", 10, "Link-Local Unicast"},
		{"ff00::", 8, "MULTICAST"},
		{"2000::", 3, "Global Unicast"},
	}
	for _, r := range recs {
		if in6(n, r.base, r.plen) {
			if r.name == "MULTICAST" {
				return multicastType(n)
			}
			desc := fmt.Sprintf("%s (%s/%d)", r.name, r.base, r.plen)
			if strings.HasPrefix(r.name, "IPv4-") {
				v4 := new(big.Int).And(n, big.NewInt(mask32)).Int64()
				desc += " = " + ntoa(v4)
			}
			return desc
		}
	}
	return "Reserved / Unassigned"
}

// bin6 renders a colored 128-bit binary string, grouped into hextets, with a
// space at the prefix boundary and the new subnet bits highlighted when the
// two masks differ (mirrors the IPv4 binary view).
func bin6(addr *big.Int, mask1, mask2 int, isNetmask bool) string {
	line := ""
	bitColor := setColor(binryColor)
	if isNetmask {
		bitColor = setColor(maskColor)
	}
	line += setColor(bitColor)
	newOn := false
	for i := 1; i <= 128; i++ {
		line += strconv.FormatInt(int64(addr.Bit(128-i)), 10)
		if i%16 == 0 && i < 128 {
			line += setColor(normlColor) + ":"
			line += setColor("oldcolor")
		}
		if i == mask1 {
			line += " "
		}
		if (i == mask1 || i == mask2) && mask1 != mask2 {
			if newOn {
				newOn = false
				line += setColor(bitColor)
			} else {
				newOn = true
				line += setColor(subntColor)
			}
		}
	}
	line += setColor(normlColor)
	return line
}

// printline6 prints one labelled IPv6 row (optionally with binary).
func printline6(label string, addr *big.Int, suffix string, mask1, mask2 int, isNetmask bool) {
	fmt.Print(setColor(normlColor))
	fmt.Printf("%-11s", label+":")
	fmt.Print(setColor(quadsColor))
	field := ntoip6(addr) + suffix
	if optPrintBits {
		fmt.Printf("%-45s", field)
		fmt.Print(bin6(addr, mask1, mask2, isNetmask))
	} else {
		fmt.Print(field)
	}
	fmt.Print(setColor(normlColor))
	fmt.Print("\n")
}

// netBlock6 prints the Network / HostMin / HostMax rows for a prefix.
func netBlock6(network *big.Int, mask, maskBin2 int) {
	host := new(big.Int).Xor(prefixlenton(mask), all128)
	last := new(big.Int).Or(network, host)
	if mask == 128 {
		printline6("Hostroute", network, fmt.Sprintf("/%d", mask), mask, maskBin2, false)
		return
	}
	printline6("Network", network, fmt.Sprintf("/%d", mask), mask, maskBin2, false)
	printline6("HostMin", network, "", mask, maskBin2, false)
	printline6("HostMax", last, "", mask, maskBin2, false)
}

func subnets6(network *big.Int, mask1, mask2 int) {
	printline6("Netmask", prefixlenton(mask2), fmt.Sprintf(" = %d", mask2), mask2, mask1, true)
	printline6("Wildcard", new(big.Int).Xor(prefixlenton(mask2), all128), "", mask2, mask1, false)
	fmt.Print("\n")

	count := pow2(mask2 - mask1)
	limit := big.NewInt(1000)
	one := big.NewInt(1)
	shift := uint(128 - mask2)
	for i := big.NewInt(0); i.Cmp(count) < 0; i.Add(i, one) {
		net := new(big.Int).Lsh(i, shift)
		net.Or(net, network)
		fmt.Printf(" %s.\n", new(big.Int).Add(i, one).String())
		netBlock6(net, mask2, mask1)
		fmt.Print("\n")
		if i.Cmp(limit) >= 0 {
			fmt.Printf("... stopped at 1000 subnets ...%s", breakStr)
			break
		}
	}
	fmt.Printf("Subnets:   %s%s%s\n", quadsColor, count.String(), normlColor)
	hostsPer := pow2(128 - mask2)
	fmt.Printf("Hosts:     %s%s%s\n", quadsColor, new(big.Int).Mul(hostsPer, count).String(), normlColor)
}

func supernet6(network *big.Int, mask1, mask2 int) {
	network = new(big.Int).And(network, prefixlenton(mask2))
	printline6("Netmask", prefixlenton(mask2), fmt.Sprintf(" = %d", mask2), mask2, mask1, true)
	printline6("Wildcard", new(big.Int).Xor(prefixlenton(mask2), all128), "", mask2, mask1, false)
	fmt.Print("\n")
	netBlock6(network, mask2, mask1)
}

func ipcalc6(address, address2 *big.Int, mask1, mask2 int) {
	prefixMask := prefixlenton(mask1)
	network := new(big.Int).And(address, prefixMask)
	host := new(big.Int).Xor(prefixMask, all128)

	fmt.Printf("%s[ %s/%d ]%s\n\n", classColor, ntoip6(address), mask1, normlColor)

	printline6("Address", address, "", mask1, mask1, false)
	// expanded form (no binary column)
	fmt.Print(setColor(normlColor))
	fmt.Printf("%-11s", "Full:")
	fmt.Print(setColor(quadsColor))
	fmt.Print(ntoexp6(address))
	fmt.Print(setColor(normlColor))
	fmt.Print("\n")
	printline6("Netmask", prefixMask, fmt.Sprintf(" = %d", mask1), mask1, mask1, true)
	printline6("Wildcard", host, "", mask1, mask1, false)

	fmt.Print("\n=>\n\n")

	netBlock6(network, mask1, mask1)

	hosts := pow2(128 - mask1)
	fmt.Print(setColor(normlColor))
	fmt.Printf("Hosts/Net: %s%s%s (2^%d)\n", quadsColor, hosts.String(), normlColor, 128-mask1)
	if mask1 < 64 {
		subs := pow2(64 - mask1)
		fmt.Printf("Subnets/64: %s%s%s (2^%d)\n", quadsColor, subs.String(), normlColor, 64-mask1)
	}
	fmt.Printf("Type:      %s%s%s\n", classColor, addrType6(address), normlColor)
	fmt.Printf("arpa:      %s%s%s\n", quadsColor, ptr6(address), normlColor)

	if optSplit {
		fmt.Print("\n")
		splitNetwork6(network, mask1, optSplitSizes)
		return
	}
	if mask1 < mask2 {
		fmt.Printf("\nSubnets after transition from /%d to /%d\n\n", mask1, mask2)
		subnets6(network, mask1, mask2)
	}
	if mask1 > mask2 {
		fmt.Print("\nSupernet\n\n")
		supernet6(network, mask1, mask2)
	}
}

// ---- converters -------------------------------------------------------

func ntoip6(n *big.Int) string {
	mask16 := big.NewInt(65535)
	slices := make([]string, 8)
	for idx, i := 0, 7; i > -1; i, idx = i-1, idx+1 {
		slice := new(big.Int).Rsh(n, uint(i*16))
		slice.And(slice, mask16)
		slices[idx] = fmt.Sprintf("%x", slice)
	}
	result := strings.Join(slices, ":")

	// compress longest run of "0"
	length := 0
	maxLength := 0
	start := 0
	for i := 0; i < 8; i++ {
		length = 0
		for (i+length < 8) && slices[i+length] == "0" {
			length++
		}
		if length > maxLength {
			start = i
			maxLength = length
		}
	}

	if maxLength > 1 { // RFC 5952: never shorten a single 16-bit zero field
		var b strings.Builder
		if start == 0 {
			b.WriteString("::")
		}
		for i := 0; i < 8; i++ {
			if !(i >= start && i < start+maxLength) {
				b.WriteString(slices[i])
				if i < 7 {
					b.WriteString(":")
				}
				if i+1 == start {
					b.WriteString(":")
				}
			}
		}
		result = b.String()
	}
	return result
}

func bitcountmaskton(bitcountmask int) int64 {
	var n int64
	for i := 0; i < bitcountmask; i++ {
		n |= 1 << uint(31-i)
	}
	return n
}

var reHexColon = regexp.MustCompile(`[0-9a-f:]`)

// ip6ton parses an IPv6 address into a 128-bit big.Int. Returns nil on error.
func ip6ton(arg string) *big.Int {
	arg = strings.ToLower(arg)
	test := reHexColon.ReplaceAllString(arg, "")
	if test != "" {
		return nil
	}
	if strings.HasPrefix(arg, "::") {
		arg = "0" + arg
	}
	if strings.HasSuffix(arg, "::") {
		arg = arg + "0"
	}
	tmp := strings.Split(arg, ":")
	// Perl's split drops trailing empty fields.
	for len(tmp) > 0 && tmp[len(tmp)-1] == "" {
		tmp = tmp[:len(tmp)-1]
	}

	var slice []string
	compressed := false
	hashTmp := len(tmp) - 1 // Perl $#tmp
	for _, s := range tmp {
		if s == "" {
			if compressed {
				return nil
			}
			for i := 0; i < 8-hashTmp; i++ {
				slice = append(slice, "0")
				compressed = true
			}
		} else {
			slice = append(slice, s)
		}
	}
	if len(slice)-1 != 7 {
		return nil
	}
	n := big.NewInt(0)
	for i := 0; i < 8; i++ {
		v, err := strconv.ParseUint(slice[i], 16, 64)
		if err != nil {
			return nil
		}
		part := new(big.Int).SetUint64(v)
		part.Lsh(part, uint(16*(7-i)))
		n.Add(n, part)
	}
	return n
}

func prefixlenton(prefixlen int) *big.Int {
	n := big.NewInt(0)
	for i := 127; i >= 128-prefixlen; i-- {
		n.SetBit(n, i, 1)
	}
	return n
}

var reMask6 = regexp.MustCompile(`^\d{1,3}$`)

func checkMask6(mask string) int {
	mask = strings.TrimPrefix(mask, "/")
	if !reMask6.MatchString(mask) {
		return -1
	}
	m, _ := strconv.Atoi(mask)
	if m < 0 || m > 128 {
		return -1
	}
	return m
}

var (
	reHexColonFull = regexp.MustCompile(`^[0-9a-fA-F:]+$`)
	reDotted       = regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$`)
	reLeadSlash    = regexp.MustCompile(`^/(\d+)$`)
	reCount        = regexp.MustCompile(`^\d{1,2}$`)
	reHex8         = regexp.MustCompile(`^[0-9A-Fa-f]{8}$`)
	reHex80x       = regexp.MustCompile(`^0x[0-9A-Fa-f]{8}$`)
)

// argton parses an address (dotted decimals, bit-count-mask, hex, or IPv6).
// Returns (v4, nil) for IPv4 results, (-1, v6) for IPv6 results, or
// (-1, nil) when invalid. When an IPv6 address is detected the global
// ipv6 flag is set, matching the original.
func argton(arg string, netmaskFlag bool) (int64, *big.Int) {
	i := 24
	var n int64

	// ipv6
	if !netmaskFlag && reHexColonFull.MatchString(arg) {
		ipv6 = true
		v6 := ip6ton(arg)
		if v6 == nil {
			return -1, nil
		}
		return -1, v6
	}

	// dotted decimals
	if m := reDotted.FindStringSubmatch(arg); m != nil {
		for k := 1; k <= 4; k++ {
			d, _ := strconv.Atoi(m[k])
			if d > 255 || d < 0 {
				return -1, nil
			}
			n += int64(d) << uint(i)
			i -= 8
		}
		if netmaskFlag {
			return validateNetmask(n), nil
		}
		return n, nil
	}

	// bit-count-mask (24 or /24)
	if lm := reLeadSlash.FindStringSubmatch(arg); lm != nil {
		arg = lm[1]
	}

	// ipv6 (per original, effectively never reached on this path)
	if ipv6 {
		if !reMask6.MatchString(arg) {
			return -1, nil
		}
		pl, _ := strconv.Atoi(arg)
		if pl < 0 || pl > 128 {
			return -1, nil
		}
		return -1, prefixlenton(pl)
	}

	// ipv4 bit-count
	if reCount.MatchString(arg) {
		cnt, _ := strconv.Atoi(arg)
		if cnt < 0 || cnt > 32 {
			return -1, nil
		}
		for k := 0; k < cnt; k++ {
			n |= 1 << uint(31-k)
		}
		return n, nil
	}

	// hex
	if reHex8.MatchString(arg) || reHex80x.MatchString(arg) {
		hexStr := strings.TrimPrefix(arg, "0x")
		v, _ := strconv.ParseUint(hexStr, 16, 64)
		if netmaskFlag {
			return validateNetmask(int64(v)), nil
		}
		return int64(v), nil
	}

	// invalid
	return -1, nil
}

func validateNetmask(mask int64) int64 {
	sawZero := false
	// negate wildcard
	if (mask & (1 << 31)) == 0 {
		fmt.Print("WILDCARD\n")
		mask = (^mask) & mask32
	}
	// find ones following zeros
	for i := 0; i < 32; i++ {
		if (mask & (1 << uint(31-i))) == 0 {
			sawZero = true
		} else {
			if sawZero {
				fmt.Print("INVALID NETMASK\n")
				return -1
			}
		}
	}
	return mask
}

func ntoa(n int64) string {
	n &= mask32
	return fmt.Sprintf("%d.%d.%d.%d", (n>>24)&255, (n>>16)&255, (n>>8)&255, n&255)
}

func ntobitcountmask(mask int64) int {
	bitcountmask := 0
	for bitcountmask < 32 && (mask&(1<<uint(31-bitcountmask))) != 0 {
		bitcountmask++
	}
	return bitcountmask
}

// ---- documentation ----------------------------------------------------

func usage() {
	fmt.Printf(`Usage: ipcalc [options] <ADDRESS>[[/]<NETMASK>] [NETMASK]

ipcalc takes an IP address and netmask and calculates the resulting
broadcast, network, Cisco wildcard mask, and host range. By giving a
second netmask, you can design sub- and supernetworks. It is also
intended to be a teaching tool and presents the results as
easy-to-understand binary values.

 -n --nocolor  Don't display ANSI color codes.
 -c --color    Display ANSI color codes (default).
 -b --nobinary Suppress the bitwise output.
 -c --class    Just print bit-count-mask of given address.
 -h --html     Display results as HTML (not finished in this version).
 -v --version  Print Version.
 -s --split n1 n2 n3
               Split into networks of size n1, n2, n3.
 -r --range    Deaggregate address range.
    --help     Longer help text.

Examples:

ipcalc 192.168.0.1/24
ipcalc 192.168.0.1/255.255.128.0
ipcalc 192.168.0.1 255.255.128.0 255.255.192.0
ipcalc 192.168.0.1 0.0.63.255

IPv6 is detected automatically and gets a full breakdown: expanded form,
prefix, host range, address count, /64 subnet count, address type (per the
IANA special-purpose registry), and the ip6.arpa reverse-DNS name.

ipcalc 2001:db8::1/64           full IPv6 breakdown
ipcalc 2001:db8::/48 64         IPv6 subnets after transition to /64
ipcalc 2001:db8:0:1::/64 48     IPv6 supernet


ipcalc <ADDRESS1> - <ADDRESS2>  deaggregate address range

ipcalc <ADDRESS>/<NETMASK> --s a b c
                                split network to subnets
				where a b c fits in.

! New HTML support not yet finished.

ipcalc %s
`, version)
}

func help() {
	fmt.Printf("    \n"+`IP Calculator %s

Enter your netmask(s) in CIDR notation (/25) or dotted decimals
(255.255.255.0). Inverse netmask are recognized. If you mmit the
netmask, ipcalc uses the default netmask for the class of your
network.

Look at the space between the bits of the addresses: The bits before
it are the network part of the address, the bits after it are the host
part. You can see two simple facts: In a network address all host bits
are zero, in a broadcast address they are all set.

The class of your network is determined by its first bits.

If your network is a private internet according to RFC 1918 this is
remarked. When displaying subnets the new bits in the network part of
the netmask are marked in a different color.

The wildcard is the inverse netmask as used for access control lists
in Cisco routers. You can also enter netmasks in wildcard notation.

Do you want to split your network into subnets? Enter the address and
netmask of your original network and play with the second netmask
until the result matches your needs.

Questions? Comments? Drop me a mail: krischan at jodies.de
http://jodies.de/ipcalc

Thanks for your nice ideas and help to make this tool more useful:`+" \n\n"+`Bartosz Fenski
Denis A. Hainsworth
Foxfair Hu
Frank Quotschalla
Hermann J. Beckers
Igor Zozulya
Kevin Ivory
Lars Mueller
Lutz Pressler
Oliver Seufer
Scott Davis
Steve Kent
Sven Anderson
Torgen Foertsch
Edward
Nick Clifford
Victor Engmark

`, version)
	usage()
}
