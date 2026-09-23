package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/transform"
)

type NamedEncoding struct {
	Name string
	Enc  encoding.Encoding
}

// Full spectrum of global single-byte and CJK multi-byte encodings
var globalEncodings = []NamedEncoding{
	// Latin / Western (Primary Mojibake Source Encodings)
	{"Windows-1252", charmap.Windows1252},
	{"ISO-8859-1", charmap.ISO8859_1},
	{"ISO-8859-15", charmap.ISO8859_15},
	{"Macintosh", charmap.Macintosh},

	// Cyrillic
	{"Windows-1251", charmap.Windows1251},
	{"CP866", charmap.CodePage866},
	{"KOI8-R", charmap.KOI8R},
	{"KOI8-U", charmap.KOI8U},
	{"ISO-8859-5", charmap.ISO8859_5},
	{"MacCyrillic", charmap.MacintoshCyrillic},

	// Central / Eastern European
	{"Windows-1250", charmap.Windows1250},
	{"ISO-8859-2", charmap.ISO8859_2},
	{"CP852", charmap.CodePage852},

	// Greek
	{"Windows-1253", charmap.Windows1253},
	{"ISO-8859-7", charmap.ISO8859_7},

	// Turkish & Baltic
	{"Windows-1254", charmap.Windows1254},
	{"Windows-1257", charmap.Windows1257},
	{"ISO-8859-9", charmap.ISO8859_9},
	{"ISO-8859-13", charmap.ISO8859_13},

	// Middle East & SE Asia
	{"Windows-1255", charmap.Windows1255}, // Hebrew
	{"Windows-1256", charmap.Windows1256}, // Arabic
	{"Windows-1258", charmap.Windows1258}, // Vietnamese
	{"Windows-874", charmap.Windows874},   // Thai

	// CJK Multi-Byte Encodings
	{"GBK", simplifiedchinese.GBK},
	{"GB18030", simplifiedchinese.GB18030},
	{"Big5", traditionalchinese.Big5},
	{"Shift-JIS", japanese.ShiftJIS},
	{"EUC-JP", japanese.EUCJP},
	{"EUC-KR", korean.EUCKR},

	// --- Simplified Chinese ---
	{"GBK", simplifiedchinese.GBK},            // Microsoft Windows CP936
	{"GB18030", simplifiedchinese.GB18030},    // National Standard (1/2/4-byte)
	{"HZ-GB2312", simplifiedchinese.HZGB2312}, // Legacy email format

	// --- Traditional Chinese ---
	{"Big5", traditionalchinese.Big5}, // Taiwan / HK standard
}

type RepairResult struct {
	FixedText  string
	Steps      []string
	Script     string
	Confidence int
}

func main() {
	var inputs []string

	if len(os.Args) > 1 {
		// Read inputs directly from command-line arguments
		inputs = os.Args[1:]
	} else {
		// If no arguments given, read line-by-line from STDIN (ideal for piping)
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					inputs = append(inputs, line)
				}
			}
		} else {
			fmt.Println("Usage:")
			fmt.Println("  go run main.go \"<garbled_string_1>\" \"<garbled_string_2>\"")
			fmt.Println("  echo \"<garbled_string>\" | go run main.go")
			os.Exit(1)
		}
	}

	for _, sample := range inputs {
		fmt.Println("Input: ", sample)
		res, ok := UniversalFix(sample)
		if ok {
			fmt.Printf("Fixed: %s\nPath:  %v\nScript: %s (Confidence: %d%%)\n",
				res.FixedText, res.Steps, res.Script, res.Confidence)
		} else {
			fmt.Println("Failed to restore text.")
		}
		fmt.Println("--------------------------------------------------")
	}
}

// UniversalFix attempts single-pass, multi-byte, and double-pass recoveries.
func UniversalFix(input string) (RepairResult, bool) {
	detector := chardet.NewTextDetector()

	// 1. Single-Pass Recovery
	if res, ok := evaluateCandidates(input, detector); ok {
		return res, true
	}

	// 2. Double-Pass Recovery (Fixes nested mojibake)
	for _, firstPass := range globalEncodings {
		rawFirst, err := encodeString(input, firstPass.Enc)
		if err != nil {
			continue
		}

		for _, secondPass := range globalEncodings {
			if firstPass.Name == secondPass.Name {
				continue
			}

			intermediate, err := decodeBytes(rawFirst, secondPass.Enc)
			if err != nil {
				continue
			}

			if res, ok := evaluateCandidates(intermediate, detector); ok {
				res.Steps = append([]string{firstPass.Name + "->" + secondPass.Name}, res.Steps...)
				return res, true
			}
		}
	}

	return RepairResult{}, false
}

// evaluateCandidates tests all target encodings against a byte representation of the input.
func evaluateCandidates(input string, detector *chardet.Detector) (RepairResult, bool) {
	var best RepairResult

	// Track whether input is primarily Western Latin extended characters (Mojibake signature)
	inputIsLatinMojibake := isLatinExtended(input)

	for _, source := range globalEncodings {
		raw, err := encodeString(input, source.Enc)
		if err != nil {
			continue
		}

		for _, target := range globalEncodings {
			if source.Name == target.Name {
				continue
			}

			// Skip trivial overlaps between Windows-1252, ISO-8859-1, and ISO-8859-15
			if isLatinOverlap(source.Name, target.Name) {
				continue
			}

			decoded, err := decodeBytes(raw, target.Enc)
			if err != nil {
				continue
			}

			// If input was already Latin Mojibake, ignore fixes that produce pure Latin again
			confidence, script := detectQuality(decoded, detector)
			if inputIsLatinMojibake && script == "Latin" {
				continue
			}

			if confidence > best.Confidence {
				best = RepairResult{
					FixedText:  decoded,
					Steps:      []string{source.Name + " -> " + target.Name},
					Script:     script,
					Confidence: confidence,
				}
			}
		}
	}

	if best.Confidence >= 50 {
		return best, true
	}
	return best, false
}

func isLatinOverlap(a, b string) bool {
	latinEncs := map[string]bool{
		"Windows-1252": true,
		"ISO-8859-1":   true,
		"ISO-8859-15":  true,
		"Macintosh":    true,
	}
	return latinEncs[a] && latinEncs[b]
}

func isLatinExtended(s string) bool {
	var total, latinExt float64
	for _, r := range s {
		if unicode.IsLetter(r) {
			total++
			if unicode.Is(unicode.Latin, r) && r > 127 {
				latinExt++
			}
		}
	}
	return total > 0 && (latinExt/total) > 0.3
}

func encodeString(s string, enc encoding.Encoding) ([]byte, error) {
	r := transform.NewReader(bytes.NewReader([]byte(s)), enc.NewEncoder())
	return io.ReadAll(r)
}

func decodeBytes(b []byte, enc encoding.Encoding) (string, error) {
	r := transform.NewReader(bytes.NewReader(b), enc.NewDecoder())
	out, err := io.ReadAll(r)
	return string(out), err
}

// detectQuality scores candidate text using character set detection + Unicode script ranges.
func detectQuality(s string, detector *chardet.Detector) (int, string) {
	if len(s) == 0 {
		return 0, "Unknown"
	}

	// Calculate target script density
	var totalLetters float64
	scriptCounts := make(map[string]float64)

	for _, r := range s {
		if unicode.IsLetter(r) {
			totalLetters++
			switch {
			case unicode.Is(unicode.Latin, r):
				scriptCounts["Latin"]++
			case unicode.Is(unicode.Cyrillic, r):
				scriptCounts["Cyrillic"]++
			case unicode.Is(unicode.Greek, r):
				scriptCounts["Greek"]++
			case unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hangul, r):
				scriptCounts["CJK"]++
			case unicode.Is(unicode.Hebrew, r):
				scriptCounts["Hebrew"]++
			case unicode.Is(unicode.Arabic, r):
				scriptCounts["Arabic"]++
			case unicode.Is(unicode.Thai, r):
				scriptCounts["Thai"]++
			}
		}
	}

	if totalLetters == 0 {
		return 0, "Unknown"
	}

	var mainScript string
	var maxCount float64
	for script, count := range scriptCounts {
		if count > maxCount {
			maxCount = count
			mainScript = script
		}
	}

	densityScore := (maxCount / totalLetters) * 100

	// Complement with statistical chardet match if available
	results, err := detector.DetectAll([]byte(s))
	chardetConfidence := 0
	if err == nil && len(results) > 0 {
		chardetConfidence = results[0].Confidence
	}

	// Combined score
	finalScore := int((densityScore * 0.7) + (float64(chardetConfidence) * 0.3))
	return finalScore, mainScript
}
