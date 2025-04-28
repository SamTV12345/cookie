package cookie

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RegExp to match cookie-name in RFC 6265 sec 4.1.1
// This refers out to the obsoleted definition of token in RFC 2616 sec 2.2
// which has been replaced by the token definition in RFC 7230 appendix B.
//
// cookie-name       = token
// token             = 1*tchar
// tchar             = "!" / "#" / "$" / "%" / "&" / "'" /
//
//	"*" / "+" / "-" / "." / "^" / "_" /
//	"`" / "|" / "~" / DIGIT / ALPHA
//
// Note: Allowing more characters - https://github.com/jshttp/cookie/issues/191
// Allow same range as cookie value, except `=`, which delimits end of name.
var cookieNameRegExp = regexp.MustCompile("^[\x21-\x3A\x3C\x3E-\x7E]*$")

// RegExp to match cookie-value in RFC 6265 sec 4.1.1
//
// cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
// cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
//
//	 ; US-ASCII characters excluding CTLs,
//	 ; whitespace DQUOTE, comma, semicolon,
//	; and backslash
//
// Allowing more characters: https://github.com/jshttp/cookie/issues/191
// Comma, backslash, and DQUOTE are not part of the parsing algorithm.
var cookieValueRegExp = regexp.MustCompile("^[\x21-\x3A\x3C-\x7E]*$")

// RegExp to match domain-value in RFC 6265 sec 4.1.1
//
// domain-value      = <subdomain>
//
//	; defined in [RFC1034], Section 3.5, as
//	; enhanced by [RFC1123], Section 2.1
//
// <subdomain>       = <label> | <subdomain> "." <label>
// <label>           = <let-dig> [ [ <ldh-str> ] <let-dig> ]
//
//	 Labels must be 63 characters or less.
//	'let-dig' not 'letter' in the first char, per RFC1123
//
// <ldh-str>         = <let-dig-hyp> | <let-dig-hyp> <ldh-str>
// <let-dig-hyp>     = <let-dig> | "-"
// <let-dig>         = <letter> | <digit>
// <letter>          = any one of the 52 alphabetic characters A through Z in
//
//	upper case and a through z in lower case
//
// <digit>           = any one of the ten digits 0 through 9
//
// Keep support for leading dot: https://github.com/jshttp/cookie/issues/173
//
// > (Note that a leading %x2E ("."), if present, is ignored even though that
// character is not permitted, but a trailing %x2E ("."), if present, will
// cause the user agent to ignore the attribute.)
var domainValueRegExp = regexp.MustCompile("^([.]?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")

// RegExp to match path-value in RFC 6265 sec 4.1.1
//
// path-value        = <any CHAR except CTLs or ";">
// CHAR              = %x01-7F
//
//	; defined in RFC 5234 appendix B.1
var pathValueRegExp = regexp.MustCompile("^[\x20-\x3A\x3D-\x7E]*$")

type ParseOptions interface {
	// Decode
	//Specifies a function that will be used to decode a [cookie-value](https://datatracker.ietf.org/doc/html/rfc6265#section-4.1.1).
	// Since the value of a cookie has a limited character set (and must be a simple string), this function can be used to decode
	// a previously-encoded cookie value into a JavaScript string.
	//
	// The default function is the global `decodeURIComponent`, wrapped in a `try..catch`. If an error
	// is thrown it will return the cookie's original value. If you provide your own encode/decode
	// scheme you must ensure errors are appropriately handled.
	//
	// @default decode
	//
	Decode(str string) (string, error)
}

func IndexOf(str, substr string, position int) int {
	strLen := len(str)

	if position >= strLen {
		return -1
	}

	if position < 0 {
		position = 0
	}

	index := strings.Index(str[position:], substr)
	if index == -1 {
		return -1
	}

	return index + position
}

func LastIndex(str, substr string, position int) int {
	strLen := len(str)

	if position >= strLen {
		return -1
	}

	if position < 0 {
		position = 0
	}

	index := strings.LastIndex(str[:position], substr)
	if index == -1 {
		return -1
	}

	return index
}

func Parse(str string, options ParseOptions) map[string]interface{} {
	obj := make(map[string]interface{})
	lenOfStr := len(str)
	// RFC 6265 sec 4.1.1, RFC 2616 2.2 defines a cookie name consists of one char minimum, plus '='.
	if lenOfStr < 2 {
		return obj
	}

	var dec func(string) (string, error)
	if options != nil {
		dec = (options).Decode
	} else {
		dec = decode
	}
	index := 0

	for {
		eqIdx := IndexOf(str, "=", index)
		if eqIdx == -1 {
			break
		}

		var colonIdx = IndexOf(str, ";", index)
		var endIndex int

		if colonIdx == -1 {
			endIndex = lenOfStr
		} else {
			endIndex = colonIdx
		}

		if eqIdx > endIndex {
			// backtrack on prior semicolon
			index = LastIndex(str, ";", eqIdx-1) + 1
			continue
		}

		keyStartIdx := StartIndex(str, index, eqIdx)
		keyEndIdx := EndIndex(str, eqIdx, keyStartIdx)
		key := str[keyStartIdx:keyEndIdx]

		// only assign once
		if obj[key] == nil {
			valStartIndex := StartIndex(str, eqIdx+1, endIndex)
			valEndIdx := EndIndex(str, endIndex, valStartIndex)

			value, err := dec(str[valStartIndex:valEndIdx])
			if err != nil {
				value = "Error decoding cookie value"
			}
			obj[key] = value
		}

		index = endIndex + 1
		if !(index < lenOfStr) {
			break
		}
	}
	return obj
}

type EncodeOptions interface {
	Encode(string) (string, error)
}

type PriorityType string

const (
	PriorityLow    PriorityType = "Low"
	PriorityMedium PriorityType = "Medium"
	PriorityHigh   PriorityType = "High"
)

type SameSite string

const (
	SameSiteTrue   SameSite = "true"
	SameSiteLax    SameSite = "lax"
	SameSiteStrict SameSite = "strict"
	SameSiteNone   SameSite = "none"
	SameSiteFalse  SameSite = "false"
)

type EncodeFunc = func(string) (string, error)

type SerializeOptions struct {
	encode []EncodeFunc
	// MaxAge
	// Specifies the `number` (in seconds) to be the value for the [`Max-Age` `Set-Cookie` attribute](https://tools.ietf.org/html/rfc6265#section-5.2.2).
	//
	// The [cookie storage model specification](https://tools.ietf.org/html/rfc6265#section-5.3) states that if both `expires` and
	// `maxAge` are set, then `maxAge` takes precedence, but it is possible not all clients by obey this,
	// so if both are set, they should point to the same date and time.
	//
	MaxAge *int
	// Expires
	// Specifies the `Date` object to be the value for the [`Expires` `Set-Cookie` attribute](https://tools.ietf.org/html/rfc6265#section-5.2.1).
	// When no expiration is set clients consider this a "non-persistent cookie" and delete it the current session is over.
	//
	// The [cookie storage model specification](https://tools.ietf.org/html/rfc6265#section-5.3) states that if both `expires` and
	//`maxAge` are set, then `maxAge` takes precedence, but it is possible not all clients by obey this,
	// so if both are set, they should point to the same date and time.
	//
	Expires *time.Time
	// Domain
	// Specifies the value for the [`Domain` `Set-Cookie` attribute](https://tools.ietf.org/html/rfc6265#section-5.2.3).
	// When no domain is set clients consider the cookie to apply to the current domain only.
	//
	Domain *string
	// Path
	// Specifies the value for the [`Path` `Set-Cookie` attribute](https://tools.ietf.org/html/rfc6265#section-5.2.4).
	// When no path is set, the path is considered the ["default path"](https://tools.ietf.org/html/rfc6265#section-5.1.4).
	//
	Path *string
	// HttpOnly
	// Enables the [`HttpOnly` `Set-Cookie` attribute](https://tools.ietf.org/html/rfc6265#section-5.2.6).
	// When enabled, clients will not allow client-side JavaScript to see the cookie in `document.cookie`.
	//
	HttpOnly *bool
	// Secure
	// Enables the [`Secure` `Set-Cookie` attribute](https://tools.ietf.org/html/rfc6265#section-5.2.5).
	// When enabled, clients will only send the cookie back if the browser has a HTTPS connection.
	//
	Secure *bool
	// Partitioned
	// Enables the [`Partitioned` `Set-Cookie` attribute](https://tools.ietf.org/html/draft-cutler-httpbis-partitioned-cookies/).
	// When enabled, clients will only send the cookie back when the current domain _and_ top-level domain matches.
	//
	// This is an attribute that has not yet been fully standardized, and may change in the future.
	// This also means clients may ignore this attribute until they understand it. More information
	// about can be found in [the proposal](https://github.com/privacycg/CHIPS).
	//
	Partitioned *bool
	// Priority
	// Specifies the value for the [`Priority` `Set-Cookie` attribute](https://tools.ietf.org/html/draft-west-cookie-priority-00#section-4.1).
	//
	// - `'low'` will set the `Priority` attribute to `Low`.
	// - `'medium'` will set the `Priority` attribute to `Medium`, the default priority when not set.
	// - `'high'` will set the `Priority` attribute to `High`.
	//
	// More information about priority levels can be found in [the specification](https://tools.ietf.org/html/draft-west-cookie-priority-00#section-4.1).
	//
	Priority *PriorityType
	// SameSite
	// Specifies the value for the [`SameSite` `Set-Cookie` attribute](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-09#section-5.4.7).
	//
	// - `true` will set the `SameSite` attribute to `Strict` for strict same site enforcement.
	// - `'lax'` will set the `SameSite` attribute to `Lax` for lax same site enforcement.
	// - `'none'` will set the `SameSite` attribute to `None` for an explicit cross-site cookie.
	// - `'strict'` will set the `SameSite` attribute to `Strict` for strict same site enforcement.
	//
	// More information about enforcement levels can be found in [the specification](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-09#section-5.4.7).
	//
	SameSite *SameSite
}

func (s *SerializeOptions) SetEncode(encode EncodeFunc) {
	s.encode = []EncodeFunc{
		encode,
	}
}

type ArgumentNameInvalid string

func (e ArgumentNameInvalid) Error() string {
	return fmt.Sprintf("Invalid argument name: %s", string(e))
}

type ValueInvalid string

func (e ValueInvalid) Error() string {
	return fmt.Sprintf("Invalid cookie value: %s", string(e))
}

type DomainInvalid string

func (e DomainInvalid) Error() string {
	return fmt.Sprintf("Invalid domain value: %s", string(e))
}

type PathInvalid string

func (e PathInvalid) Error() string {
	return fmt.Sprintf("Invalid path value: %s", string(e))
}

type SameSiteInvalid string

func (e SameSiteInvalid) Error() string {
	return fmt.Sprintf("Invalid SameSite value: %s", string(e))
}

func Serialize(name string, val string, options *SerializeOptions) (*string, error) {

	if !cookieNameRegExp.MatchString(name) {
		return nil, ArgumentNameInvalid(name)
	}

	var value string
	if options != nil && options.encode != nil && len(options.encode) > 0 {
		var returnType, err = options.encode[0](val)
		if err != nil {
			return nil, err
		}
		value = returnType
	} else {
		value = url.QueryEscape(val)
		if strings.Contains(value, "+") {
			value = strings.ReplaceAll(value, "+", "%20")
		}
	}

	if !cookieValueRegExp.MatchString(value) {
		return nil, ValueInvalid(value)
	}

	str := name + "=" + value
	if options == nil {
		return &str, nil
	}

	if options.MaxAge != nil {
		str += "; Max-Age=" + strconv.Itoa(*options.MaxAge)
	}

	if options.Domain != nil {
		if !domainValueRegExp.MatchString(*options.Domain) {
			return nil, DomainInvalid(*options.Domain)
		}
		str += "; Domain=" + *options.Domain
	}

	if options.Path != nil {
		if !pathValueRegExp.MatchString(*options.Path) {
			return nil, PathInvalid(*options.Path)
		}
		str += "; Path=" + *options.Path
	}

	if options.HttpOnly != nil && *options.HttpOnly {
		str += "; HttpOnly"
	}

	if options.Expires != nil {
		str += "; Expires=" + options.Expires.Format(http.TimeFormat)
	}

	if options.Secure != nil && *options.Secure {
		str += "; Secure"
	}

	if options.Partitioned != nil && *options.Partitioned {
		str += "; Partitioned"
	}

	if options.Priority != nil {
		str += "; Priority=" + string(*options.Priority)
	}

	if options.SameSite != nil {
		switch *options.SameSite {
		case SameSiteTrue:
			str += "; SameSite=Strict"
		case SameSiteStrict:
			str += "; SameSite=Strict"
			break
		case SameSiteLax:
			str += "; SameSite=Lax"
			break
		case SameSiteNone:
			str += "; SameSite=None"
			break
		case SameSiteFalse:
		default:
			return nil, SameSiteInvalid(*options.SameSite)
		}
	}

	return &str, nil
}

func StartIndex(str string, index int, max int) int {
	for {
		// Javascript returns NaN while go panics
		if len(str) > index {
			var code = str[index]
			if code != 0x20 && code != 0x09 {
				return index
			}
		}
		index++
		if !(index < max) {
			break
		}
	}
	return max
}

func EndIndex(str string, index int, min int) int {
	for index > min {
		index = index - 1
		if len(str) > index {
			var code = str[index]
			if code != 0x20 && code != 0x09 {
				return index + 1
			}
		}
	}
	return min
}

func decode(str string) (string, error) {
	if strings.Index(str, "%") == -1 {
		return str, nil
	}
	dateQuery, err := url.PathUnescape(str)
	if err != nil {
		return str, nil
	}
	return dateQuery, nil
}
