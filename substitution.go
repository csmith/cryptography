package cryptography

import "strings"

// CaesarShift performs a caesar shift of the given amount on all a-z/A-Z characters. All other characters are
// left intact.
func CaesarShift(input []byte, count uint8) []byte {
	return CaesarShiftKeyed(input, []uint8{count})
}

// CaesarShiftKeyed performs a caesar shift on all a-z/A-Z characters. The amount of the shift can vary for each
// character and is provided in the counts array. If the counts array is shorter than the input array, it will be
// repeated. All other characters are left intact.
func CaesarShiftKeyed(input []byte, counts []uint8) []byte {
	builder := strings.Builder{}

	shift := func(c, min byte, count uint8) byte {
		res := c - min
		for res < min {
			res += 26
		}
		return min + (res+count)%26
	}

	ops := 0
	for i := range input {
		c := input[i]
		if c >= 'a' && c <= 'z' {
			builder.WriteByte(shift(c, 'a', counts[ops % len(counts)]))
			ops++
		} else if c >= 'A' && c <= 'Z' {
			builder.WriteByte(shift(c, 'A', counts[ops % len(counts)]))
			ops++
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

// A1Z26Encode replaces each letter of the alphabet with its corresponding ordinal, from A=1 to Z=26. Non-alphabet
// characters are ignored.
func A1Z26Encode(input []byte) []uint8 {
	var res []uint8
	for i := range input {
		c := input[i]
		if c >= 'a' && c <= 'z' {
			res = append(res, 1 + c - 'a')
		} else if c >= 'A' && c <= 'Z' {
			res = append(res, 1 + c - 'A')
		}
	}
	return res
}
