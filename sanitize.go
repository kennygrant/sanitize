// Package sanitize provides functions for sanitizing text.
package sanitize

import (
	"bytes"
	"html/template"
	"path"
	"regexp"
	"strings"
)

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

	// In case we have missed any tags above, escape the text - removes <, >, &, ' and ". 
	output = template.HTMLEscapeString(output)

	// Remove a few common harmless entities, to arrive at something more like plain text
	// This relies on having removed *all* tags above
	output = strings.Replace(output, "&nbsp;", " ", -1)
	output = strings.Replace(output, "&quot;", "\"", -1)
	output = strings.Replace(output, "&apos;", "'", -1)
	output = strings.Replace(output, "&#34;", "\"", -1)
	output = strings.Replace(output, "&#39;", "'", -1)
	output = strings.Replace(output, "&amp; ", "& ", -1)     // NB space here is important, allow & not part of entity
	output = strings.Replace(output, "&amp;amp; ", "& ", -1) // Again, NB space, deal with double amps from original &amp; in text

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
