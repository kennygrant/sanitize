// Package sanitize provides functions for sanitizing text.
package sanitize

import (
	"bytes"
	"html/template"
	"path"
	"regexp"
	"strings"
)

// Strip html tags, replace common entities, and escape < and > in the result.
// Later could consider taking options and allowing certain tags, attributes etc
func HTML(s string) (output string) {
	// Does not use a regexp, but a simple set of replacement rules and a naive parser which strips all < >
	// Could also take options ,options...map[string]string
	// see rails sanitize, could have list of allowed tags, attributes etc
	// would then need a proper state machine for parsing, possibly just built using yacc or similar

	output = ""

	// Shortcut strings with no tags in them
	if !strings.ContainsAny(s, "<>") {
		output = s
	} else {
		// First replace line breaks with newlines, to preserve that formatting
		s = strings.Replace(s, "</p>", "\n", -1)
		s = strings.Replace(s, "<br>", "\n", -1)
		s = strings.Replace(s, "</br>", "\n", -1)

		// Walk through the string removing anything which is surrounded by braces
		// A VERY simple state machine which will only function on well-formed HTML
		// Note malformed html without closing > will simply be remove all text after first <
		inTag := false
		for _, r := range s {
			c := string(r)
			if c == "<" {
				inTag = true
			} else if c == ">" {
				inTag = false
			} else if !inTag {
				output = output + c
			}

		}

	}

	// In case we have missed any tags above, escape the text
	// // <, >, &, ' and ". 
	output = template.HTMLEscapeString(output)

	// Undo any unecessary entities created by html escape, as this will be plain text
	output = strings.Replace(output, "&amp;amp;", "&", -1)
	output = strings.Replace(output, "&amp;", "&", -1)
	output = strings.Replace(output, "&nbsp;", " ", -1)
	output = strings.Replace(output, "&quot;", "\"", -1)
	output = strings.Replace(output, "&apos;", "'", -1)
	output = strings.Replace(output, "&#34;", "\"", -1)
	output = strings.Replace(output, "&#39;", "'", -1)

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
		if transliterations[c] > 0 {
			b.WriteRune(transliterations[c])
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// A very limited list of transliterations to catch common european names translated to urls.
// This set could be expanded with at least caps and many more characters. 
var transliterations = map[rune]rune{
	'é': 'e',
	'è': 'e',
	'ç': 'c',
	'â': 'a',
	'å': 'a',
	'ü': 'u',
	'ï': 'i',
	'ø': 'o',
	'ö': 'o',
	'ô': 'o',
}
