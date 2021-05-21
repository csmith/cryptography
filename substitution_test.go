package cryptography

import (
	"reflect"
	"testing"
)

func TestCaesarShift(t *testing.T) {
	tests := []struct {
		name  string
		query string
		count int
		want  string
	}{
		{"empty", "", 1, ""},
		{"no rotation", "abcde", 0, "abcde"},
		{"other chars", "_#A#/B-C", 1, "_#B#/C-D"},
		{"positive", "Btusb jodmjobou, tfe opo pcmjhbou", 1, "Cuvtc kpenkpcpv, ugf pqp qdnkicpv"},
		{"26", "Btusb jodmjobou, tfe opo pcmjhbou", 26, "Btusb jodmjobou, tfe opo pcmjhbou"},
		{"40", "Btusb jodmjobou, tfe opo pcmjhbou", 40, "Phigp xcraxcpci, hts cdc dqaxvpci"},
		{"negative", "Btusb jodmjobou, tfe opo pcmjhbou", -5, "Wopnw ejyhejwjp, oaz jkj kxhecwjp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CaesarShift([]byte(tt.query), uint8(tt.count)); !reflect.DeepEqual(got, []byte(tt.want)) {
				t.Errorf("CaesarShift() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCaesarShiftKeyed(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		counts []int
		want   string
	}{
		{"empty", "", []int{1, 2, 3}, ""},
		{"no rotation", "abcde", []int{0, 0}, "abcde"},
		{"other chars", "_#A#/B-C", []int{1}, "_#B#/C-D"},
		{"alternating", "Btusb jodmjobou, tfe opo pcmjhbou", []int{1, 2}, "Cvvuc lpfnlpdpw, uhf qqq qenlidpw"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counts := make([]uint8, len(tt.counts))
			for i := range tt.counts {
				counts[i] = uint8(tt.counts[i])
			}
			if got := CaesarShiftKeyed([]byte(tt.query), counts); !reflect.DeepEqual(got, []byte(tt.want)) {
				t.Errorf("CaesarShiftKeyed() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCaesarShifts(t *testing.T) {
	input := []byte("lorem ipsum doler sit")
	output := CaesarShifts(input)

	for i := 0; i < 26; i++ {
		want := CaesarShift(input, uint8(i))
		if !reflect.DeepEqual(output[i], want) {
			t.Errorf("CaesarShift()[0] = %s, want %s", output[0], want)
		}
	}
}

func TestA1Z26Encode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{"empty", "", nil},
		{"non a-z chars", "_#=!", nil},
		{"lowercase", "abc-xyz", []int{1, 2, 3, 24, 25, 26}},
		{"uppercase", "ABC-XYZ", []int{1, 2, 3, 24, 25, 26}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var want []uint8
			for i := range tt.want {
				want = append(want, uint8(tt.want[i]))
			}

			if got := A1Z26Encode([]byte(tt.input)); !reflect.DeepEqual(got, want) {
				t.Errorf("A1Z26Encode() = %#v, want %#v", got, want)
			}
		})
	}
}
