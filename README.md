sanitize
========

Package sanitize provides functions for sanitizing text in golang strings.

FUNCTIONS
___

```go
func HTMLAllowing(s string, args...[]string) (string, error)
```

Parse html and allow certain tags and attributes from the lists optionally specified by args - args[0] is a list of allowed tags, args[1] is a list of allowed attributes. If either is missing default sets are used. 


```go
func HTML(s string) string
```

Strip html tags with a very simple parser, replace common entities, and escape < and > in the result. 


```go
func Accents(text string) string
```

Replace a set of accented characters with ascii equivalents.

```go
func Name(text string) string
```

Makes a string safe to use in a file name (e.g. for saving file atttachments)

```go
func Path(text string) string
```

Makes a string safe to use as an url path, cleaned of unsuitable characters

