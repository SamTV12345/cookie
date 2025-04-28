package cookie

import (
	"encoding/base64"
	"errors"
	"testing"
)

func TestShouldParseCookieStringToMap(t *testing.T) {
	resultMap := Parse("foo=bar", nil)
	if resultMap["foo"] != "bar" {
		t.Errorf("Expected foo=bar but got %v", resultMap["foo"])
	}

	resultMap = Parse("foo=123;", nil)
	if resultMap["foo"] != "123" {
		t.Errorf("Expected foo=123 but got %v", resultMap["foo"])
	}
}

func TestShouldParseWithErrorInDecoder(t *testing.T) {

}

func TestShouldIgnoreOWS(t *testing.T) {
	var mapOfParse = Parse("FOO    = bar;   baz  =   raz", nil)
	if mapOfParse["FOO"] != "bar" {
		t.Errorf("Expected FOO=bar but got %v", mapOfParse)
	}

	if mapOfParse["baz"] != "raz" {
		t.Errorf("Expected baz=raz but got %v", mapOfParse)
	}
}

func TestShouldParseCookieWithEmptyValue(t *testing.T) {
	var result = Parse("foo=; bar=", nil)
	if result["foo"] != "" {
		t.Errorf("Expected foo='' but got %v", result["foo"])
	}
	if result["bar"] != "" {
		t.Errorf("Expected bar='' but got %v", result["bar"])
	}
}

func TestShouldParseCookieWithMinimumLength(t *testing.T) {
	result1 := Parse("f=", nil)
	if result1["f"] != "" {
		t.Errorf("Expected f='' but got %v", result1["f"])
	}
	result2 := Parse("f=;b=", nil)
	if result2["f"] != "" {
		t.Errorf("Expected f='' but got %v", result2["f"])
	}
	if result2["b"] != "" {
		t.Errorf("Expected b='' but got %v", result2["b"])
	}
}

func TestShouldUrlDecodeValues(t *testing.T) {
	var result = Parse("foo=\"bar=123456789&name=Magic+Mouse\"", nil)
	if result["foo"] != "\"bar=123456789&name=Magic+Mouse\"" {
		t.Errorf("Expected foo=bar=123456789&name=Magic Mouse but got %v", result["foo"])
	}
}

func TestShouldParseEmailCookie(t *testing.T) {
	result := Parse("email=%20%22%2c%3b%2f", nil)
	if result["email"] != " \",;/" {
		t.Errorf("Expected email=' , but got %v", result["email"])
	}
}

func TestShouldTrimWhitespaceAroundKeyAndValue(t *testing.T) {
	result := Parse("  foo  =  \"bar\"  ", nil)
	if result["foo"] != "\"bar\"" {
		t.Errorf("Expected foo=\"bar\" but got %v", result["foo"])
	}
	result = Parse("  foo  =  bar  ;  fizz  =  buzz  ", nil)
	if result["foo"] != "bar" {
		t.Errorf("Expected foo=bar but got %v", result["foo"])
	}
	if result["fizz"] != "buzz" {
		t.Errorf("Expected fizz=buzz but got %v", result["fizz"])
	}

	// Test: ' foo = " a b c " '
	result = Parse(" foo = \" a b c \" ", nil)
	if result["foo"] != "\" a b c \"" {
		t.Errorf("Expected foo='\" a b c \"' but got %v", result["foo"])
	}

	// Test: ' = bar '
	result = Parse(" = bar ", nil)
	if result[""] != "bar" {
		t.Errorf("Expected ''='bar' but got %v", result[""])
	}

	// Test: ' foo = '
	result = Parse(" foo = ", nil)
	if result["foo"] != "" {
		t.Errorf("Expected foo='' but got %v", result["foo"])
	}

	// Test: '   =   '
	result = Parse("   =   ", nil)
	if result[""] != "" {
		t.Errorf("Expected ''='' but got %v", result[""])
	}

	// Test: '\tfoo\t=\tbar\t'
	result = Parse("\tfoo\t=\tbar\t", nil)
	if result["foo"] != "bar" {
		t.Errorf("Expected foo='bar' but got %v", result["foo"])
	}
}

func TestShouldReturnOriginalValueOnEscapeError(t *testing.T) {
	result := Parse("foo=%1;bar=bar", nil)
	if result["foo"] != "%1" {
		t.Errorf("Expected foo='percent1' but got %v", result["foo"])
	}
	if result["bar"] != "bar" {
		t.Errorf("Expected bar='bar' but got %v", result["bar"])
	}
}

func TestShouldIgnoreCookiesWithoutValue(t *testing.T) {
	result := Parse("foo=bar;fizz  ;  buzz", nil)
	if result["foo"] != "bar" {
		t.Errorf("Expected foo=bar but got %v", result["foo"])
	}

	result = Parse("  fizz; foo=  bar", nil)
	if result["foo"] != "bar" {
		t.Errorf("Expected foo=bar but got %v", result["foo"])
	}
}

func TestShouldIgnoreDuplicateCookies(t *testing.T) {
	result := Parse("foo=%1;bar=bar;foo=boo", nil)
	if result["foo"] != "%1" || result["bar"] != "bar" {
		t.Errorf("Expected map[foo:%%1 bar:bar] but got %v", result)
	}

	result = Parse("foo=false;bar=bar;foo=true", nil)
	if result["foo"] != "false" || result["bar"] != "bar" {
		t.Errorf("Expected map[foo:false bar:bar] but got %v", result)
	}

	result = Parse("foo=;bar=bar;foo=boo", nil)
	if result["foo"] != "" || result["bar"] != "bar" {
		t.Errorf("Expected map[foo: bar:bar] but got %v", result)
	}
}

type Base64ParseOptions struct {
}

func (p *Base64ParseOptions) Decode(str string) (string, error) {
	base64Rep, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", err
	}
	return string(base64Rep), nil
}

func TestParseTooShortCookie(t *testing.T) {
	result := Parse("f", nil)
	if len(result) != 0 {
		t.Errorf("Expected foo=bar but got %v", result["foo"])
	}
}

func TestShouldParseNativeProperties(t *testing.T) {
	result := Parse("toString=foo;valueOf=bar", nil)
	if result["toString"] != "foo" || result["valueOf"] != "bar" {
		t.Errorf("Expected map[toString:foo valueOf:bar] but got %v", result)
	}
}

func TestShouldParseWithDecodingFunction(t *testing.T) {
	b := Base64ParseOptions{}

	result := Parse("foo=YmFy", &b)
	if result["foo"] != "bar" {
		t.Errorf("Expected foo=bar but got %v", result)
	}
}

type InvalidDecoder struct {
}

func (d *InvalidDecoder) Decode(str string) (string, error) {
	return str, errors.New("invalid decoder")
}

func TestShouldParseWithErrorsInDecoding(t *testing.T) {
	b := InvalidDecoder{}

	result := Parse("foo=YmFy", &b)
	if result["foo"] != "Error decoding cookie value" {
		t.Errorf("Expected foo=bar but got %v", result)
	}
}
