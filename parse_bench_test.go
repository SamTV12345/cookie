package cookie

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

func benchCookie(str string, b *testing.B) {
	for b.Loop() {
		Parse(str, nil)
	}
}

func BenchmarkParseSimply(b *testing.B) {
	benchCookie("foo=bar", b)
}

func BenchmarkDecode(b *testing.B) {
	benchCookie("foo=hello%20there!", b)
}

func BenchmarkUnquote(b *testing.B) {
	benchCookie("foo=\"foo bar\"", b)
}

func BenchmarkDuplicates(b *testing.B) {
	benchCookie(genCookies(2), b)
}

func Benchmark10Duplicates(b *testing.B) {
	benchCookie(genCookies(10), b)
}

func Benchmark100Duplicates(b *testing.B) {
	benchCookie(genCookies(100), b)
}

func BenchmarkTopSites(b *testing.B) {
	var cookies, err = loadCookiesFromFile("./scripts/parse-top.json")
	if err != nil {
		b.Fatal(err)
	}

	keysOfCookies := make([]string, 0, len(cookies))
	for k := range cookies {
		keysOfCookies = append(keysOfCookies, k)
	}

	sort.Strings(keysOfCookies)

	for _, k := range keysOfCookies {
		b.Run(k, func(b *testing.B) {
			benchCookie(cookies[k], b)
		})
	}
}

func loadCookiesFromFile(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cookies map[string]string
	if err := json.NewDecoder(file).Decode(&cookies); err != nil {
		return nil, err
	}
	return cookies, nil
}

func genCookies(num int) string {
	var str = ""
	for i := 0; i < num; i++ {
		str += "foo" + string(rune(i)) + "=bar" + string(rune(i)) + "; "
	}
	return str
}
