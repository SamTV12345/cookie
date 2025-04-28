# Go cookie library


This cookie library is a reimplementation of the [NodeJS cookie](https://www.npmjs.com/package/cookie) library.
It allows parsing but also serializing cookies.

Parsing a cookie with multiple values:
```go
	result := cookie.Parse("foo=bar;fizz  ;  buzz", nil)
	fmt.Println(result) // map[foo:bar fizz:buzz]
```

Serializing a cookie:
```go
	result, err := Serialize("foo", "bar", nil)
```

It features the same data structures as the NodeJS library, so you can use it in a similar way.
It is also possible to add a custom decoder functions to the parser.

