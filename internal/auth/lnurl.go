package auth

import "strings"

func EncodeLNURL(rawURL string) (string, error) {
	data, err := convertBits([]byte(rawURL), 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32Encode("lnurl", data)
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := uint32(0)
	bits := uint(0)
	maxv := uint32((1 << toBits) - 1)
	var ret []byte
	for _, val := range data {
		acc = (acc << fromBits) | uint32(val)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, byte((acc>>bits)&maxv))
		}
	}
	if pad && bits > 0 {
		ret = append(ret, byte((acc<<(toBits-bits))&maxv))
	}
	return ret, nil
}

func bech32Encode(hrp string, data []byte) (string, error) {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

	values := make([]byte, 0, len(hrp)*2+1+len(data)+6)
	for _, c := range hrp {
		values = append(values, byte(c>>5))
	}
	values = append(values, 0)
	for _, c := range hrp {
		values = append(values, byte(c&31))
	}
	values = append(values, data...)
	values = append(values, 0, 0, 0, 0, 0, 0)

	polymod := bech32Polymod(values) ^ 1
	checksum := make([]byte, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = byte((polymod >> uint(5*(5-i))) & 31)
	}

	combined := append(data, checksum...)
	ret := strings.ToLower(hrp) + "1"
	for _, d := range combined {
		ret += string(charset[d])
	}
	return ret, nil
}

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}
