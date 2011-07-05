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
	


// Table for Base64 decoding
// TODO: Which is better: the map or this array? I imagine the array lookup is faster but haven't benchmarked it
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
	
/* For reference here is the map version (should benchmark)
var index_64 = map[byte] byte {
	46:0, 47:1, 48:54, 49:55,
	50:56, 51:57, 52:58, 53:59, 54:60, 55:61, 56:62, 57:63,
	65:2, 66:3, 67:4, 68:5, 69:6,
	70:7, 71:8, 72:9, 73:10, 74:11, 75:12, 76:13, 77:14, 78:15, 79:16,
	80:17, 81:18, 82:19, 83:20, 84:21, 85:22, 86:23, 87:24, 88:25, 89:26,
	90:27, 97:28, 98:29, 99:30, 
	100:31, 101:32, 102:33, 103:34, 104:35, 105:36, 106:37, 107:38, 108:39, 109:40,
	110:41, 111:42, 112:43, 113:44, 114:45, 115:46, 116:47, 117:48, 118:49, 119:50,
	120:51, 121:52, 122:53 }
*/


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

func char64(x byte) (byte, os.Error) {
	rs := index_64[x]
	if rs >= 0 {
		return byte(rs), nil
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
