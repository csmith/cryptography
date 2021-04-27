package cryptography

import "strings"

// CaesarShift performs a caesar shift of the given amount on all a-z/A-Z characters. All other characters are
// left intact.
func CaesarShift(input []byte, count uint8) []byte {
	builder := strings.Builder{}

	shift := func(c, min byte) byte {
		res := c - min
		for res < min {
			res += 26
		}
		return min + (res+count)%26
	}

	for i := range input {
		c := input[i]
		if c >= 'a' && c <= 'z' {
			builder.WriteByte(shift(c, 'a'))
		} else if c >= 'A' && c <= 'Z' {
			builder.WriteByte(shift(c, 'A'))
		} else {
			builder.WriteByte(c)
		}
	}
	return []byte(builder.String())
}

// CaesarShifts performs all 25 possible caesar shifts on the input.
func CaesarShifts(input []byte) [26][]byte {
	var res [26][]byte
	res[0] = input
	for i := 1; i <= 25; i++ {
		res[i] = CaesarShift(input, uint8(i))
	}
	return res
}
