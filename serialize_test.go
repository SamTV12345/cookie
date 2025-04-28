package cookie

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestShouldSerializeNameAndValue(t *testing.T) {
	var cookieStr, err = Serialize("foo", "bar", nil)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *cookieStr != "foo=bar" {
		t.Errorf("Expected foo=bar but got %v", cookieStr)
	}
}

func TestShouldUrlEncodeValue(t *testing.T) {
	var cookieStr, err = Serialize("foo", "bar +baz", nil)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *cookieStr != "foo=bar%20%2Bbaz" {
		t.Errorf("Expected foo=bar +baz but got %v", *cookieStr)
	}
}

func TestShouldSerializeEmptyValue(t *testing.T) {
	serializedEmptyValue, err := Serialize("foo", "", nil)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *serializedEmptyValue != "foo=" {
		t.Errorf("Expected nil but got %v", *serializedEmptyValue)
	}
}

func TestShouldHandleSpecialCharacters(t *testing.T) {
	cookieInput := []string{
		"foo",
		"foo,bar",
		"foo!bar",
		"foo#bar",
		"foo$bar",
		"foo'bar",
		"foo*bar",
		"foo+bar",
		"foo-bar",
		"foo.bar",
		"foo^bar",
		"foo_bar",
		"foo`bar",
		"foo|bar",
		"foo~bar",
		"foo7bar",
		"foo/bar",
		"foo@bar",
		"foo[bar",
		"foo]bar",
		"foo:bar",
		"foo{bar",
		"foo}bar",
		"foo\"bar",
		"foo<bar",
		"foo>bar",
		"foo?bar",
		"foo\\bar",
	}
	for _, name := range cookieInput {
		t.Run(name, func(t *testing.T) {
			var serialized, err = Serialize(name, "baz", nil)
			if err != nil {
				t.Errorf("Expected no error but got %v", err)
			}
			var expected = name + "=baz"
			if *serialized != expected {
				t.Errorf("Expected %s=baz but got >%v<", name, *serialized)
			}
		})
	}
}

func TestShouldThrowForInvalidName(t *testing.T) {
	var cookie = []string{
		"foo\n",
		"foo\u280a",
		"foo=bar",
		"foo;bar",
		"foo bar",
		"foo\tbar",
	}

	for _, name := range cookie {
		t.Run(name, func(t *testing.T) {
			_, err := Serialize(name, "baz", nil)
			if err == nil {
				t.Errorf("Expected error but got nil")
			}
			var serr = ArgumentNameInvalid("Test")
			if !errors.As(err, &serr) {
				t.Errorf("Expected ArgumentNameInvalid but got %v", err)
			}
		})
	}
}

func TestCookieSerializeWithDomainOption(t *testing.T) {
	domain := []string{
		"example.com",
		"sub.example.com",
		".example.com",
		"localhost",
		".localhost",
		"my-site.org",
	}

	for _, d := range domain {
		t.Run(d, func(t *testing.T) {
			serializeOptions := SerializeOptions{
				Domain: &d,
			}
			var cookieStr, err = Serialize("foo", "bar", &serializeOptions)
			if err != nil {
				t.Errorf("Expected no error but got %v", err)
			}
			if *cookieStr != "foo=bar; Domain="+d {
				t.Errorf("Expected foo=bar; Domain=%s but got %v", d, *cookieStr)
			}
		})
	}
}

func TestShouldThrowForInvalidDomain(t *testing.T) {
	domain := []string{
		"example.com\n",
		"sub.example.com\u0000",
		"my site.org",
		"domain..com",
		"example.com; Path=/",
		"example.com /* inject a comment */",
	}

	for _, d := range domain {
		t.Run(d, func(t *testing.T) {
			serializeOptions := SerializeOptions{
				Domain: &d,
			}
			_, err := Serialize("foo", "bar", &serializeOptions)
			if err == nil {
				t.Errorf("Expected error but got nil")
			}
			var serr = DomainInvalid("Test")
			if !errors.As(err, &serr) {
				t.Errorf("Expected DomainNameInvalid but got %v", err)
				if !strings.HasPrefix(err.Error(), "Invalid domain name") {
					t.Errorf("Expected Invalid domain name but got %v", err)
				}
			}
		})
	}
}

func TestShouldSpecifyAlternativeValueDecoder(t *testing.T) {
	serializeOptions := SerializeOptions{}
	var encodeFunc = func(str string) (string, error) {
		base64Rep := base64.StdEncoding.EncodeToString(bytes.NewBufferString(str).Bytes())
		return base64Rep, nil
	}
	var encFunc = encodeFunc

	serializeOptions.SetEncode(encFunc)

	var cookieStr, err = Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *cookieStr != "foo=YmFy" {
		t.Errorf("Expected foo=YmFy but got %v", *cookieStr)
	}
}

func TestShouldReturnAlternativeDecoderError(t *testing.T) {
	serializeOptions := SerializeOptions{}
	var encodeFunc = func(str string) (string, error) {
		return "", errors.New("errors")
	}
	var encFunc = encodeFunc

	serializeOptions.SetEncode(encFunc)

	var _, err = Serialize("foo", "bar", &serializeOptions)
	if err == nil {
		t.Errorf("Expected error but got nil")
	}
}

func TestIndexOfBiggerPositionThanLength(t *testing.T) {
	position := IndexOf("test", "t", 500)
	if position != -1 {
		t.Errorf("Expected -1 but got %d", position)
	}
}

func TestIndexOfNegativePosition(t *testing.T) {
	position := IndexOf("test", "t", -1)
	if position != 0 {
		t.Errorf("Expected 0 but got %d", position)
	}
}

func TestLastIndexOfZeroPosition(t *testing.T) {
	position := LastIndex("test", "t", -1)
	if position != -1 {
		t.Errorf("Expected 0 but got %d", position)
	}
}

func TestLastIndexPositionGreaterThanStrLength(t *testing.T) {
	position := LastIndex("test", "t", 500)
	if position != -1 {
		t.Errorf("Expected -1 but got %d", position)
	}
}

func TestShouldSerializeValue(t *testing.T) {
	var strArr = []string{
		"foo=bar",
		"foo\"bar",
		"foo,bar",
		"foo\\bar",
		"foo$bar",
	}

	serializeOptions := SerializeOptions{}
	var encodeFunc = func(str string) (string, error) {
		return str, nil
	}
	var encFunc = encodeFunc

	serializeOptions.SetEncode(encFunc)

	for _, str := range strArr {
		t.Run(str, func(t *testing.T) {
			var cookieStr, err = Serialize("foo", str, &serializeOptions)
			if err != nil {
				t.Errorf("Expected no error but got %v", err)
			}
			if *cookieStr != "foo="+str {
				t.Errorf("Expected foo=%s but got %v", str, *cookieStr)
			}
		})
	}
}

func TestShouldThrowSerializeArgumentValue(t *testing.T) {
	var cookies = []string{
		"+\n",
		"foo bar",
		"foo\tbar",
		"foo;bar",
		"foo\u280a",
	}

	serializeOptions := SerializeOptions{}
	var encodeFunc = func(str string) (string, error) {
		return str, nil
	}
	var encFunc = encodeFunc

	serializeOptions.SetEncode(encFunc)

	for _, str := range cookies {
		_, err := Serialize("foo", str, &serializeOptions)
		if err == nil {
			t.Errorf("Expected error for invalid cookie value but got nil")
		}
		var serr = ValueInvalid("t")
		if !errors.As(err, &serr) {
			t.Errorf("Expected ValueInvalid but got %v", err)
		}
	}
}

func TestShouldSetExpiresToGivenDate(t *testing.T) {
	expiry := time.Date(2000, 12, 24, 10, 30, 59, 0, time.UTC)
	serializeOptions := SerializeOptions{
		Expires: &expiry,
	}
	var cookieStr, err = Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *cookieStr != "foo=bar; Expires=Sun, 24 Dec 2000 10:30:59 GMT" {
		t.Errorf("Expected foo=bar; Expires=Sun, 24 Dec 2000 10:30:59 GMT but got %v", *cookieStr)
	}
}

func TestShouldWithHttpOnlyOption(t *testing.T) {
	httpOnly := true
	var serializeOptions = SerializeOptions{
		HttpOnly: &httpOnly,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if *result != "foo=bar; HttpOnly" {
		t.Errorf("Expected foo=bar; HttpOnly but got %v", *result)
	}
}

func TestShouldWithHttpOnlyOptionFalse(t *testing.T) {
	httpOnly := false
	var serializeOptions = SerializeOptions{
		HttpOnly: &httpOnly,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if *result != "foo=bar" {
		t.Errorf("Expected foo=bar but got %v", *result)
	}
}

func TestShouldWithMaxAgeOption(t *testing.T) {
	maxAge := 1000
	var serializeOptions = SerializeOptions{
		MaxAge: &maxAge,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar; Max-Age=1000" {
		t.Errorf("Expected foo=bar; Max-Age=1000 but got %v", *result)
	}

	var maxAge2 = 0
	serializeOptions.MaxAge = &maxAge2
	result, err = Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar; Max-Age=0" {
		t.Errorf("Expected foo=bar; Max-Age=0 but got %v", *result)
	}
}

func TestShouldNotSetMaxAgeWhenUndefined(t *testing.T) {
	var serializeOptions = SerializeOptions{}
	serializeOptions.MaxAge = nil
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar" {
		t.Errorf("Expected foo=bar but got %v", *result)
	}
}

func TestShouldIncludePartitionedFlagWhenTrue(t *testing.T) {
	partitioned := true
	var serializeOptions = SerializeOptions{
		Partitioned: &partitioned,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar; Partitioned" {
		t.Errorf("Expected foo=bar; Partitioned but got %v", *result)
	}
}

func TestShouldIncludePartitionedFlagWhenFalse(t *testing.T) {
	partitioned := false
	var serializeOptions = SerializeOptions{
		Partitioned: &partitioned,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar" {
		t.Errorf("Expected foo=bar but got %v", *result)
	}
}

func TestShouldIncludePartitionedFlagWhenNil(t *testing.T) {
	var serializeOptions = SerializeOptions{
		Partitioned: nil,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar" {
		t.Errorf("Expected foo=bar but got %v", *result)
	}
}

func TestShouldIncludeWithPathOption(t *testing.T) {
	var validPaths = []string{
		"/",
		"/login",
		"/foo.bar/baz",
		"/foo-bar",
		"/foo=bar?baz",
		"/foo\"bar\"",
		"/../foo/bar",
		"../foo/",
		"./",
	}

	for _, path := range validPaths {
		t.Run(path, func(t *testing.T) {

			serializedCookie, err := Serialize("foo", "bar", &SerializeOptions{
				Path: &path,
			})
			if err != nil {
				t.Errorf("Expected no error but got %v", err)
			}
			if *serializedCookie != "foo=bar; Path="+path {
				t.Errorf("Expected foo=bar; Path=%s but got %v", path, *serializedCookie)
			}
		})
	}
}

func TestShouldThrowForInvalidPath(t *testing.T) {
	var invalidPaths = []string{
		"/\n",
		"/foo\u0000",
		"/path/with\rnewline",
		"/; Path=/sensitive-data",
		"/login\"><script>alert(1)</script>",
	}

	for _, path := range invalidPaths {
		t.Run(path, func(t *testing.T) {
			_, err := Serialize("foo", "bar", &SerializeOptions{
				Path: &path,
			})
			if err == nil {
				t.Errorf("Expected error but got %v", err)
			}
			var serr = PathInvalid("t")
			if !errors.As(err, &serr) {
				t.Errorf("Expected PathInvalid but got %v", err)
			}
		})
	}
}

func TestShouldSetToLowPriority(t *testing.T) {
	var lowPriority = PriorityLow
	var serializeOptions = SerializeOptions{
		Priority: &lowPriority,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar; Priority=Low" {
		t.Errorf("Expected foo=bar; Priority=Low but got %v", *result)
	}
}

func TestShouldSetToMediumPriority(t *testing.T) {
	var mediumPriority = PriorityMedium
	var serializeOptions = SerializeOptions{
		Priority: &mediumPriority,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar; Priority=Medium" {
		t.Errorf("Expected foo=bar; Priority=Medium but got %v", *result)
	}
}

func TestShouldSetToHighPriority(t *testing.T) {
	var highPriority = PriorityHigh
	var serializeOptions = SerializeOptions{
		Priority: &highPriority,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar; Priority=High" {
		t.Errorf("Expected foo=bar; Priority=High but got %v", *result)
	}
}

func TestWithSameSiteOptionStrict(t *testing.T) {
	var sameSite = SameSiteStrict
	var serializeOptions = SerializeOptions{
		SameSite: &sameSite,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar; SameSite=Strict" {
		t.Errorf("Expected foo=bar; SameSite=Lax but got %v", *result)
	}
}

func TestWithSameSiteOptionLax(t *testing.T) {
	var sameSite = SameSiteLax
	var serializeOptions = SerializeOptions{
		SameSite: &sameSite,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar; SameSite=Lax" {
		t.Errorf("Expected foo=bar; SameSite=Lax but got %v", *result)
	}
}

func TestWithSameSiteOptionNone(t *testing.T) {
	var sameSite = SameSiteNone
	var serializeOptions = SerializeOptions{
		SameSite: &sameSite,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar; SameSite=None" {
		t.Errorf("Expected foo=bar; SameSite=Lax but got %v", *result)
	}
}

func TestWithSameSiteOptionTrue(t *testing.T) {
	var sameSite = SameSiteTrue
	var serializeOptions = SerializeOptions{
		SameSite: &sameSite,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar; SameSite=Strict" {
		t.Errorf("Expected foo=bar; SameSite=Lax but got %v", *result)
	}
}

func TestWithSameSiteOptionFalse(t *testing.T) {
	var sameSite = SameSiteTrue
	var serializeOptions = SerializeOptions{
		SameSite: &sameSite,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar; SameSite=Strict" {
		t.Errorf("Expected foo=bar; SameSite=Lax but got %v", *result)
	}
}

func TestWithSecureOptionTrue(t *testing.T) {
	var secure = true
	var serializeOptions = SerializeOptions{
		Secure: &secure,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar; Secure" {
		t.Errorf("Expected foo=bar; Secure but got %v", *result)
	}
}

func TestWithSecureOptionFalse(t *testing.T) {
	var secure = false
	var serializeOptions = SerializeOptions{
		Secure: &secure,
	}
	result, err := Serialize("foo", "bar", &serializeOptions)
	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}
	if *result != "foo=bar" {
		t.Errorf("Expected foo=bar but got %v", *result)
	}
}

func TestWithInvalidSameSiteOption(t *testing.T) {
	var invalidSameSite = "invalid"
	var serializeOptions = SerializeOptions{
		SameSite: (*SameSite)(&invalidSameSite),
	}
	_, err := Serialize("foo", "bar", &serializeOptions)
	var expectedError = SameSiteInvalid("Test")
	if errors.Is(err, &expectedError) {
		var serr SameSiteInvalid
		errors.As(err, &serr)
		t.Errorf("Expected error but got nil")
	}
}

func TestArgumentNameInvalid_Error(t *testing.T) {
	var err = ArgumentNameInvalid("test")
	if !strings.Contains(err.Error(), "Invalid argument name: test") {
		t.Errorf("Expected Invalid argument name: test but got %v", err)
	}
}

func TestValueInvalid_Error(t *testing.T) {
	var err = ValueInvalid("test")
	if !strings.Contains(err.Error(), "Invalid cookie value: test") {
		t.Errorf("Expected Invalid argument name: test but got %v", err)
	}
}

func TestDomainInvalid_Error(t *testing.T) {
	var err = DomainInvalid("test")
	if !strings.Contains(err.Error(), "Invalid domain value: test") {
		t.Errorf("Expected Invalid argument name: test but got %v", err)
	}
}

func TestPathInvalid_Error(t *testing.T) {
	var err = PathInvalid("test")
	if !strings.Contains(err.Error(), "Invalid path value: test") {
		t.Errorf("Expected Invalid argument name: test but got %v", err)
	}
}

func TestSameSiteInvalid_Error(t *testing.T) {
	var err = SameSiteInvalid("test")
	if !strings.Contains(err.Error(), "Invalid SameSite value: test") {
		t.Errorf("Expected Invalid argument name: test but got %v", err)
	}
}
