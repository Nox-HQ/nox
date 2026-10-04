// Package refs holds the reference predicates: executable statements of what
// a credential format IS, written from each format's published description.
//
// Nothing here is read off nox. The module this package lives in does not
// depend on nox, so it cannot call a nox validator, reuse a nox regex or
// share a nox helper even by accident. The encoders below (base62, Bech32,
// the macaroon v2 reader) are written here for that reason, even where nox
// has its own.
package refs

import (
	"encoding/base64"
	"hash/crc32"
	"strings"
)

// base62 renders n most-significant digit first over 0-9A-Za-z, left-padded
// with '0' to width. GitHub's token-format post: "a 32-bit checksum ...
// encoded in base62".
func base62(n uint32, width int) string {
	const digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var b []byte
	for n > 0 {
		b = append(b, digits[n%62])
		n /= 62
	}
	for len(b) < width {
		b = append(b, '0')
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func crc32IEEE(s string) uint32 { return crc32.ChecksumIEEE([]byte(s)) }

func allIn(s, alphabet string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(alphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}

const (
	alnum      = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	hexDigits  = "0123456789abcdefABCDEF"
	b64urlAlph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// --- Bech32, BIP-173 (https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) ---

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	var out []byte
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

// bech32Decode returns the 5-bit data (checksum stripped) when s is a valid
// BIP-173 Bech32 string. Mixed case is invalid; uppercase is folded.
func bech32Decode(s string) (hrp string, data []byte, ok bool) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, false
	}
	s = strings.ToLower(s)
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, false
	}
	hrp = s[:pos]
	for _, c := range []byte(s[pos+1:]) {
		i := strings.IndexByte(bech32Charset, c)
		if i < 0 {
			return "", nil, false
		}
		data = append(data, byte(i))
	}
	if bech32Polymod(append(bech32HRPExpand(hrp), data...)) != 1 {
		return "", nil, false
	}
	return hrp, data[:len(data)-6], true
}

func bech32Encode(hrp string, data []byte) string {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(values) ^ 1
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, d := range data {
		b.WriteByte(bech32Charset[d])
	}
	for i := 0; i < 6; i++ {
		b.WriteByte(bech32Charset[(mod>>uint(5*(5-i)))&31])
	}
	return b.String()
}

// convertBits regroups bits, BIP-173's reference convertbits.
func convertBits(data []byte, from, to uint, pad bool) ([]byte, bool) {
	acc, bits := uint32(0), uint(0)
	maxv := uint32(1)<<to - 1
	var out []byte
	for _, v := range data {
		if uint32(v)>>from != 0 {
			return nil, false
		}
		acc = acc<<from | uint32(v)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, false
	}
	return out, true
}

// b64url decodes base64url with or without padding.
func b64url(s string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	return b, err == nil
}
