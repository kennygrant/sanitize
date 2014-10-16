// Package sanitize provides functions for sanitizing text.
package sanitize

import (
	"bytes"
	"html"
	"html/template"
	"io"
	"path"
	"regexp"
	"strings"

	parser "code.google.com/p/go.net/html"
)

// Sanitize utf8 html, allowing some tags
// Usage: sanitize.HTMLAllowing("<b id=id>my html</b>",[]string{"b"},[]string{"id")
func HTMLAllowing(s string, args ...[]string) (string, error) {
	var IGNORE_TAGS = []string{"title", "script", "style", "iframe", "frame", "frameset", "noframes", "noembed", "embed", "applet", "object", "base"}
	var DEFAULT_TAGS = []string{"h1", "h2", "h3", "h4", "h5", "h6", "div", "span", "hr", "p", "br", "b", "i", "ol", "ul", "li", "a", "img"}
	var DEFAULT_ATTR = []string{"id", "class", "src", "href", "title", "alt", "name", "rel"}

	allowedTags := DEFAULT_TAGS
	if len(args) > 0 {
		allowedTags = args[0]
	}
	allowedAttributes := DEFAULT_ATTR
	if len(args) > 1 {
		allowedAttributes = args[1]
	}

	// Parse the html
	tokenizer := parser.NewTokenizer(strings.NewReader(s))

	buffer := bytes.NewBufferString("")
	ignore := ""

	for {
		tokenType := tokenizer.Next()
		token := tokenizer.Token()

		switch tokenType {

		case parser.ErrorToken:
			err := tokenizer.Err()
			if err == io.EOF {
				return buffer.String(), nil
			} else {
				return "", err
			}
		case parser.StartTagToken:

			if len(ignore) == 0 && includes(allowedTags, token.Data) {
				token.Attr = cleanAttributes(token.Attr, allowedAttributes)
				buffer.WriteString(token.String())
			} else if includes(IGNORE_TAGS, token.Data) {
				ignore = token.Data
			}

		case parser.SelfClosingTagToken:

			if len(ignore) == 0 && includes(allowedTags, token.Data) {
				token.Attr = cleanAttributes(token.Attr, allowedAttributes)
				buffer.WriteString(token.String())
			} else if token.Data == ignore {
				ignore = ""
			}

		case parser.EndTagToken:
			if len(ignore) == 0 && includes(allowedTags, token.Data) {
				token.Attr = []parser.Attribute{}
				buffer.WriteString(token.String())
			} else if token.Data == ignore {
				ignore = ""
			}

		case parser.TextToken:
			// We allow text content through, unless ignoring this entire tag and its contents (including other tags)
			if ignore == "" {
				buffer.WriteString(token.String())
			}
		case parser.CommentToken:
			// We ignore comments by default
		case parser.DoctypeToken:
			// We ignore doctypes by default - html5 does not require them and this is intended for sanitizing snippets of text
		default:
			// We ignore unknown token types by default

		}

	}

}

// Strip html tags, replace common entities, and escape <>&;'" in the result.
// Note the returned text may contain entities as it is escaped by HTMLEscapeString, and most entities are not translated.
func HTML(s string) (output string) {

	output = ""

	// Shortcut strings with no tags in them
	if !strings.ContainsAny(s, "<>") {
		output = s
	} else {

		// First remove line breaks etc as these have no meaning outside html tags (except pre)
		// this means pre sections will lose formatting... but will result in less uninentional paras.
		s = strings.Replace(s, "\n", "", -1)

		// Then replace line breaks with newlines, to preserve that formatting
		s = strings.Replace(s, "</p>", "\n", -1)
		s = strings.Replace(s, "<br>", "\n", -1)
		s = strings.Replace(s, "</br>", "\n", -1)
		s = strings.Replace(s, "<br/>", "\n", -1)

		// Walk through the string removing all tags
		b := bytes.NewBufferString("")
		inTag := false
		for _, r := range s {
			switch r {
			case '<':
				inTag = true
			case '>':
				inTag = false
			default:
				if !inTag {
					b.WriteRune(r)
				}
			}
		}
		output = b.String()
	}

	// Remove a few common harmless entities, to arrive at something more like plain text
	output = strings.Replace(output, "&#8216;", "'", -1)
	output = strings.Replace(output, "&#8217;", "'", -1)
	output = strings.Replace(output, "&#8220;", "\"", -1)
	output = strings.Replace(output, "&#8221;", "\"", -1)
	output = strings.Replace(output, "&nbsp;", " ", -1)
	output = strings.Replace(output, "&quot;", "\"", -1)
	output = strings.Replace(output, "&apos;", "'", -1)

	// Translate some entities into their plain text equivalent (for example accents, if encoded as entities)
	output = html.UnescapeString(output)

	// In case we have missed any tags above, escape the text - removes <, >, &, ' and ".
	output = template.HTMLEscapeString(output)

	// After processing, remove some harmless entities &, ' and " which are encoded by HTMLEscapeString
	output = strings.Replace(output, "&#34;", "\"", -1)
	output = strings.Replace(output, "&#39;", "'", -1)
	output = strings.Replace(output, "&amp; ", "& ", -1)     // NB space after
	output = strings.Replace(output, "&amp;amp; ", "& ", -1) // NB space after

	return output
}

// Makes a string safe to use as an url path, cleaned of .. and unsuitable characters
func Path(text string) string {
	// Start with lowercase string
	fileName := strings.ToLower(text)
	fileName = strings.Replace(fileName, "..", "", -1)
	fileName = path.Clean(fileName)
	fileName = strings.Trim(fileName, " ")

	// Replace certain joining characters with a dash
	seps, err := regexp.Compile(`[ &_=+:]`)
	if err == nil {
		fileName = seps.ReplaceAllString(fileName, "-")
	}

	// Flatten accents first
	fileName = Accents(fileName)

	// Remove all other unrecognised characters
	// we are very restrictive as this is intended for ascii url slugs
	legal, err := regexp.Compile(`[^\w\_\~\-\./]`)
	if err == nil {
		fileName = legal.ReplaceAllString(fileName, "")
	}

	// Remove any double dashes caused by existing - in name
	fileName = strings.Replace(fileName, "--", "-", -1)

	// NB this may be of length 0, caller must check
	return fileName
}

// Makes a string safe to use in a file name (e.g. for saving file atttachments)
func Name(text string) string {
	// Start with lowercase string
	fileName := strings.ToLower(text)
	fileName = path.Clean(path.Base(fileName))
	fileName = strings.Trim(fileName, " ")

	// Replace certain joining characters with a dash
	seps, err := regexp.Compile(`[ &_=+:]`)
	if err == nil {
		fileName = seps.ReplaceAllString(fileName, "-")
	}

	// Remove all other unrecognised characters - NB we do allow any printable characters
	legal, err := regexp.Compile(`[^[:alnum:]-.]`)
	if err == nil {
		fileName = legal.ReplaceAllString(fileName, "")
	}

	// Remove any double dashes caused by existing - in name
	fileName = strings.Replace(fileName, "--", "-", -1)

	// NB this may be of length 0, caller must check
	return fileName
}

// Replace a set of accented characters with ascii equivalents.
func Accents(text string) string {
	// Replace some common accent characters
	b := bytes.NewBufferString("")
	for _, c := range text {
		// Check transliterations first
		if val, ok := transliterations[c]; ok {
			b.WriteString(val)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// A very limited list of transliterations to catch common european names translated to urls.
// This set could be expanded with at least caps and many more characters.
var transliterations = map[rune]string{
	'À': "A",
	'Á': "A",
	'Â': "A",
	'Ã': "A",
	'Ä': "A",
	'Å': "AA",
	'Æ': "AE",
	'Ç': "C",
	'È': "E",
	'É': "E",
	'Ê': "E",
	'Ë': "E",
	'Ì': "I",
	'Í': "I",
	'Î': "I",
	'Ï': "I",
	'Ð': "D",
	'Ł': "L",
	'Ñ': "N",
	'Ò': "O",
	'Ó': "O",
	'Ô': "O",
	'Õ': "O",
	'Ö': "O",
	'Ø': "OE",
	'Ù': "U",
	'Ú': "U",
	'Ü': "U",
	'Û': "U",
	'Ý': "Y",
	'Þ': "Th",
	'ß': "ss",
	'à': "a",
	'á': "a",
	'â': "a",
	'ã': "a",
	'ä': "a",
	'å': "aa",
	'æ': "ae",
	'ç': "c",
	'è': "e",
	'é': "e",
	'ê': "e",
	'ë': "e",
	'ì': "i",
	'í': "i",
	'î': "i",
	'ï': "i",
	'ð': "d",
	'ł': "l",
	'ñ': "n",
	'ń': "n",
	'ò': "o",
	'ó': "o",
	'ô': "o",
	'õ': "o",
	'ō': "o",
	'ö': "o",
	'ø': "oe",
	'ś': "s",
	'ù': "u",
	'ú': "u",
	'û': "u",
	'ū': "u",
	'ü': "u",
	'ý': "y",
	'þ': "th",
	'ÿ': "y",
	'ż': "z",
	'Œ': "OE",
	'œ': "oe",
}

func includes(a []string, s string) bool {
	for _, as := range a {
		if as == s {
			return true
		}
	}
	return false
}

func cleanAttributes(a []parser.Attribute, allowed []string) []parser.Attribute {
	if len(a) == 0 {
		return a
	}

	cleaned := make([]parser.Attribute, 0)
	for _, attr := range a {
		if includes(allowed, attr.Key) {

			// If the attribute contains data: or javascript: anywhere, ignore it
			// we don't allow this in attributes as it is so frequently used for xss
			// NB we allow spaces in the value, and lowercase
			re := regexp.MustCompile(`(d\s*a\s*t\s*a|j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*)\s*:`)
			val := strings.ToLower(attr.Val)
			if re.FindString(val) != "" {
				attr.Val = ""
			}

			// We are far more restrictive with href attributes
			// The url may start with /, mailto://, http:// or https://
			if attr.Key == "href" {
				urlre := regexp.MustCompile(`\A/[^/\\]?|mailto://|http://|https://`)
				if urlre.FindString(strings.ToLower(attr.Val)) == "" {
					attr.Val = ""
				}
			}

			if attr.Val != "" {
				cleaned = append(cleaned, attr)
			}
		}
	}
	return cleaned
}
