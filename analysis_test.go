package cryptography

import (
	"math"
	"reflect"
	"testing"
)

const epsilon = 0.00001

func TestIndexOfCoincidence(t *testing.T) {
	tests := []struct {
		name string
		text string
		want float64
	}{
		{"empty", "", 0.0},
		{"no repeats", "abcdefg", 0.0},
		{"basic repeat", "abcdefga", 0.03571},
		{"english text", "To be, or not to be, that is the question", 0.09655},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IndexOfCoincidence([]byte(tt.text)); math.Abs(got-tt.want) > epsilon {
				t.Errorf("IndexOfCoincidence() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLetterDistribution(t *testing.T) {
	tests := []struct {
		name string
		text string
		want [26]int
	}{
		{"Empty", "", [26]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"Mixed case", "aaAAaa", [26]int{6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"Other chars", "a_A!a a123a#a", [26]int{6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"All chars", "abcdefghijklmnopqrstuvwxyz", [26]int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LetterDistribution([]byte(tt.text)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LetterDistribution() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  float64
	}{
		{"empty", "", 0},
		{"repeated", "aaaaaaaaa", 0},
		{"english text", "Simplicity is prerequisite for reliability", 3.77233},
		{"random hex", "faa833", 1.91829},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShannonEntropy([]byte(tt.input)); math.Abs(got-tt.want) > epsilon {
				t.Errorf("ShannonEntropy() = %v, want %v", got, tt.want)
			}
		})
	}
}
