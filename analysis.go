package cryptography

import "math"

// IndexOfCoincidenceEnglish is the expected Index of Coincidence for English text.
const IndexOfCoincidenceEnglish = float64(1.73) / 26

// IndexOfCoincidence calculates the Index of Coincidence of the given text. The IoC is a measure of how likely it
// is for two randomly-drawn letters to be identical.
//
// Some sources include a normalising factor for comparing different alphabets. This is not included in this
// implementation, but can be trivially obtained by multiplying the result by 26.
func IndexOfCoincidence(text []byte) float64 {
	dist := LetterDistribution(text)
	sum, total := 0, 0
	for i := range dist {
		sum += dist[i] * (dist[i] - 1)
		total += dist[i]
	}
	return float64(sum) / float64(total*(total-1))
}

// LetterDistribution counts the number of the occurrences of each English letter (ignoring case).
func LetterDistribution(input []byte) [26]int {
	var res [26]int
	for i := range input {
		if input[i] >= 'a' && input[i] <= 'z' {
			res[input[i]-'a']++
		}
		if input[i] >= 'A' && input[i] <= 'Z' {
			res[input[i]-'A']++
		}
	}
	return res
}

const (
	// EntropyLow is the threshold below which the Shannon Entropy implies very little variation in the input
	EntropyLow = 0.5
	// EntropyEnglishStart is the lower-bound for the Shannon Entropy of typical English Text.
	EntropyEnglishStart = 3.5
	// EntropyEnglishEnd is the upper-bound for the Shannon Entropy of typical English Text.
	EntropyEnglishEnd = 5
	// EntropyCompressed is the threshold above which the Shannon Entropy implies the data is random/encrypted/compressed.
	EntropyCompressed = 7.5
)

// ShannonEntropy calculates the Shannon Entropy of the input. The Shannon Entropy is a measure of how much
// "information" is represented by the input.
func ShannonEntropy(input []byte) float64 {
	var occurrences [256]float64
	for i := range input {
		occurrences[input[i]]++
	}

	var size = float64(len(input))
	var entropy float64 = 0
	for i := range occurrences {
		if occurrences[i] > 0 {
			prob := occurrences[i] / size
			entropy -= prob * math.Log2(prob)
		}
	}
	return entropy
}
