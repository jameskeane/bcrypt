package bcrypt

import (
	"fmt"
	"bytes"
	"os"
)

// Table for Base64 encoding
var base64_code = [...]byte{
	'.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
	'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
	'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
	'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
	'6', '7', '8', '9'}

// TODO: This needs to be a map, i.e. index_64 := map[byte] byte{ ... }
// Table for Base64 decoding
var index_64 = []int8{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, 0, 1, 54, 55,
	56, 57, 58, 59, 60, 61, 62, 63, -1, -1,
	-1, -1, -1, -1, -1, 2, 3, 4, 5, 6,
	7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
	-1, -1, -1, -1, -1, -1, 28, 29, 30,
	31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, -1, -1, -1, -1, -1}


// Base64

func encode_base64(d []byte, leng int) string {
	off := 0
	rs := bytes.NewBufferString("")

	if leng <= 0 || leng > len(d) {
		// TODO: not really necessary, as it is a private function. But....
		return "" //, os.NewError("Invalid len")
	}

	for off < leng {
		c1 := d[off] & 0xff
		off++
		fmt.Fprint(rs, string(base64_code[(c1>>2)&0x3f]))
		c1 = (c1 & 0x03) << 4
		if off >= leng {
			fmt.Fprint(rs, string(base64_code[c1&0x3f]))
			break
		}
		c2 := d[off] & 0xff
		off++
		c1 |= (c2 >> 4) & 0x0f
		fmt.Fprint(rs, string(base64_code[c1&0x3f]))
		c1 = (c2 & 0x0f) << 2
		if off >= leng {
			fmt.Fprint(rs, string(base64_code[c1&0x3f]))
			break
		}
		c2 = d[off] & 0xff
		off++
		c1 |= (c2 >> 6) & 0x03
		fmt.Fprint(rs, string(base64_code[c1&0x3f]))
		fmt.Fprint(rs, string(base64_code[c2&0x3f]))
	}
	return string(rs.Bytes())
}
/*
func encode_base64(d []byte) (string) {
	off := 0;
	rs := bytes.NewBufferString("");
	len := len(d);

	for off < len {
		c1 := d[off] & 0xff; off++;
		fmt.Fprint(rs, string(base64_code[(c1 >> 2) & 0x3f]));
		c1 = (c1 & 0x03) << 4;
		if (off >= len) {
			fmt.Fprint(rs, string(base64_code[c1 & 0x3f]));
			break;
		}
		c2 := d[off] & 0xff; off++;
		c1 |= (c2 >> 4) & 0x0f;
		fmt.Fprint(rs, string(base64_code[c1 & 0x3f]));
		c1 = (c2 & 0x0f) << 2;
		if (off >= len) {
			fmt.Fprint(rs, string(base64_code[c1 & 0x3f]));
			break;
		}
		c2 = d[off] & 0xff; off++
		c1 |= (c2 >> 6) & 0x03;
		fmt.Fprint(rs, string(base64_code[c1 & 0x3f]));
		fmt.Fprint(rs, string(base64_code[c2 & 0x3f]));
	}
	return string(rs.Bytes())
}*/

func char64(x byte) (byte, os.Error) {
	if int(x) < len(index_64) {
		rs := index_64[x]
		if rs >= 0 {
			return byte(rs), nil
		}
	}

	return 0, os.NewError("bcrypt: Invalid base64 character")
}

func decode_base64(s string, maxolen uint) ([]byte, os.Error) {
	ret := bytes.NewBufferString("")
	olen := uint(0)
	off := 0
	slen := len(s)

	for off < (slen-1) && olen < maxolen {
		c1, err := char64(s[off])
		off++
		if err != nil {
			return nil, err
		}

		c2, err := char64(s[off])
		off++
		if err != nil {
			return nil, err
		}

		o := byte(c1 << 2)
		o |= (c2 & 0x30) >> 4
		ret.WriteByte(o)
		olen++
		if olen >= maxolen || off >= slen {
			break
		}

		c3, err := char64(s[off])
		off++
		if err != nil {
			return nil, err
		}

		o = byte((c2 & 0x0f) << 4)
		o |= (c3 & 0x3c) >> 2
		ret.WriteByte(o)
		olen++
		if olen >= maxolen || off >= slen {
			break
		}

		c4, err := char64(s[off])
		off++
		if err != nil {
			return nil, err
		}
		o = byte((c3 & 0x03) << 6)
		o |= c4
		ret.WriteByte(o)
		olen++
	}

	return ret.Bytes(), nil
}
