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
				t.Errorf("CaesarShift() = %v, want %v", got, tt.want)
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
			t.Errorf("CaesarShift()[0] = %v, want %v", output[0], want)
		}
	}
}
