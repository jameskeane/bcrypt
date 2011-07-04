package bcrypt

import (
	"os"
	"fmt"
	"bytes"
	"strconv"
	"strings"
	"bufio"
	"crypto/rand"
)

var (
	InvalidRounds = os.NewError("invalid rounds")
	InvalidSalt   = os.NewError("invalid salt")
)

const (
	MaxRounds      = 31
	MinRounds      = 4
	DefaultRounds  = 12
	SaltLen        = 16
	BlowfishRounds = 16
)

// Helper function to build the bcrypt hash string
func build_bcrypt_str(minor byte, rounds uint, payload ...string) string {
	rs := bytes.NewBufferString("")
	fmt.Fprint(rs, "$2")
	if minor >= 'a' {
		fmt.Fprint(rs, string(minor))
	}
	fmt.Fprint(rs, "$")
	if rounds < 10 {
		fmt.Fprint(rs, "0")
	}
	fmt.Fprint(rs, rounds)
	fmt.Fprint(rs, "$")
	for _, p := range payload {
		fmt.Fprint(rs, string(p))
	}
	return string(rs.Bytes())
}

// Salt generation
func Salt(rounds ...int) (string, os.Error) {
	r := DefaultRounds
	if len(rounds) > 0 {
		r = rounds[0]
		if r < MinRounds || r > MaxRounds {
			return "", InvalidRounds
		}
	}

	rnd := make([]byte, SaltLen)
	read, err := rand.Read(rnd)
	if read != SaltLen || err != nil {
		return "", os.NewError("bcrypt: Could not read the required random bytes")
	}

	return build_bcrypt_str('a', uint(r), encode_base64(rnd, len(rnd))), nil
}

// SaltBytes provides a []byte based wrapper to Salt.
//
func SaltBytes(rounds int) (salt []byte, err os.Error) {
	b, err := Salt(rounds)
	return []byte(b), err
}

func consume(r *bufio.Reader, b byte) bool {
	got, err := r.ReadByte()
	if err != nil {
		return false
	}
	if got != b {
		r.UnreadByte()
		return false
	}

	return true
}

func Hash(password string, salt ...string) (hash string, err os.Error) {
	var s string

	if len(salt) == 0 {
		s, err = Salt()
		if err != nil {
			return
		}
	} else if len(salt) == 1 {
		s = salt[0]
	} else {
		return "", InvalidSalt
	}

	// Ok, extract the required information
	minor := byte(0)
	sr := bufio.NewReader(strings.NewReader(s))

	if !consume(sr, '$') || !consume(sr, '2') {
		return "", InvalidSalt
	}

	if !consume(sr, '$') {
		minor, _ = sr.ReadByte()
		if minor != 'a' || !consume(sr, '$') {
			return "", InvalidSalt
		}
	}

	rounds_bytes := make([]byte, 2)
	read, err := sr.Read(rounds_bytes)
	if err != nil || read != 2 {
		return "", InvalidSalt
	}

	if !consume(sr, '$') {
		return "", InvalidSalt
	}

	var rounds uint
	rounds, err = strconv.Atoui(string(rounds_bytes))
	if err != nil {
		return "", InvalidSalt
	}

	salt_bytes := make([]byte, 22)
	read, err = sr.Read(salt_bytes)
	if err != nil || read != 22 {
		return "", InvalidSalt
	}

	var saltb []byte
	real_salt := string(salt_bytes)
	saltb, err = decode_base64(real_salt, SaltLen)
	if err != nil {
		return "", InvalidSalt
	}

	// TODO: ARGH	
	password += "\000"

	B := newCipher()
	hashed := B.crypt_raw([]byte(password), saltb, rounds)
	return build_bcrypt_str(minor, rounds, real_salt, encode_base64(hashed, len(bf_crypt_ciphertext)*4-1)), nil
}

// HashBytes provides a []byte based wrapper to Hash.
//
func HashBytes(password []byte, salt ...[]byte) (hash []byte, err os.Error) {
	var s string
	if len(salt) == 0 {
		s, err = Hash(string(password))
	} else {
		s, err = Hash(string(password), string(salt[0]))
	}
	return []byte(s), err
}


// Match determines if an unencrypted password matches a previously encrypted
// password. It does so by generating a Blowfish encrypted hash of the
// unencrypted password and the random salt from the previously encrypted
// password.
//
// Returns 'true' when the encrypted passwords match, otherwise 'false'.
//
func Match(password, hash string) bool {
	h, err := Hash(password, hash)
	if err != nil {
		return false
	}
	return h == hash
}

// MatchBytes provides a []byte based wrapper to Match.
//
func MatchBytes(password, hash []byte) bool {
	return Match(string(password), string(hash))
}
