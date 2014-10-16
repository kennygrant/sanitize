// Utility functions for working with text
package sanitize

import (
	"testing"
)

var Format string = "\ninput:    %q\nexpected: %q\noutput:   %q"

type Test struct {
	input    string
	expected string
}

var urls = []Test{
	{"ReAd ME.md", `read-me.md`},
	{"E88E08A7-279C-4CC1-8B90-86DE0D70443C.html", `e88e08a7-279c-4cc1-8b90-86de0d70443c.html`},
	{"/user/test/I am a long url's_-?ASDF@£$%£%^testé.html", `/user/test/i-am-a-long-urls-asdfteste.html`},
	{"/../../4-icon.jpg", `/4-icon.jpg`},
	{"/Images/../4-icon.jpg", `/images/4-icon.jpg`},
	{"../4 icon.*", `/4-icon.`},
	{"Spac ey/Name/test før url", `spac-ey/name/test-foer-url`},
	{"../*", `/`},
}

func TestPath(t *testing.T) {
	for _, test := range urls {
		output := Path(test.input)
		if output != test.expected {
			t.Fatalf(Format, test.input, test.expected, output)
		}
	}
}

var fileNames = []Test{
	{"ReAd ME.md", `read-me.md`},
	{"/var/etc/jobs/go/go/src/pkg/foo/bar.go", `bar.go`},
	{"I am a long url's_-?ASDF@£$%£%^é.html", `i-am-a-long-urls-asdf.html`},
	{"/../../4-icon.jpg", `4-icon.jpg`},
	{"/Images/../4-icon.jpg", `4-icon.jpg`},
	{"../4 icon.jpg", `4-icon.jpg`},
}

func TestName(t *testing.T) {
	for _, test := range fileNames {
		output := Name(test.input)
		if output != test.expected {
			t.Fatalf(Format, test.input, test.expected, output)
		}
	}
}

// Test with some malformed or malicious html
// NB because we remove all tokens after a < until the next >
// and do not attempt to parse, we should be safe from invalid html,
// but will sometimes completely empty the string if we have invalid input
// Note we sometimes use " in order to keep things on one line and use the ` character
var htmlTests = []Test{
	{`&nbsp;`, " "},
	{`&amp;#x000D;`, `&amp;#x000D;`},
	{`<invalid attr="invalid"<,<p><p><p><p><p>`, ``},
	{"<b><p>Bold </b> Not bold</p>\nAlso not bold.", "Bold  Not bold\nAlso not bold."},
	{`FOO&#x000D;ZOO`, "FOO\rZOO"},
	{`<script><!--<script </s`, ``},
	{`<a href="/" alt="Fab.com | Aqua Paper Map 22"" title="Fab.com | Aqua Paper Map 22" - fab.com">test</a>`, `test`},
	{`<p</p>?> or <p id=0</p> or <<</>><ASDF><@$!@£M<<>>>>>>>>>>>>>><>***************aaaaaaaaaaaaaaaaaaaaaaaaaa>`, ` or ***************aaaaaaaaaaaaaaaaaaaaaaaaaa`},
	{`<p>Some text</p><frameset src="testing.html"></frameset>`, "Some text\n"},
	{`Something<br/>Some more`, "Something\nSome more"},
	{`<a href="http://www.example.com"?>This is a 'test' of <b>bold</b> &amp; <i>italic</i></a> <br/> invalid markup.<//data>><alert><script CDATA[:Asdfjk2354115nkjafdgs]>. <div src=">">><><img src="">`, "This is a 'test' of bold & italic \n invalid markup.. \""},
	{`<![CDATA[<sender>John Smith</sender>]]>`, `John Smith]]`},
	{`<!-- <script src='blah.js' data-rel='fsd'> --> This is text`, ` -- This is text`},
	{`<style>body{background-image:url(http://www.google.com/intl/en/images/logo.gif);}</style>`, `body{background-image:url(http://www.google.com/intl/en/images/logo.gif);}`},
	{`&lt;iframe src="" attr=""&gt;>>>>>`, `&lt;iframe src="" attr=""&gt;`},
	{`<IMG """><SCRIPT>alert("XSS")</SCRIPT>">`, `alert("XSS")"`},
	{`<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>`, ``},
	{`<IMG SRC=JaVaScRiPt:alert('XSS')&gt;`, ``},
	{`<IMG SRC="javascript:alert('XSS')" <test`, ``},
	{`&gt & test &lt`, `&gt; & test &lt;`},
	{`<img></IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>`, ``},
	{`&#8220;hello&#8221; it&#8217;s for &#8216;real&#8217;`, `"hello" it's for 'real'`},
}

func TestHTML(t *testing.T) {
	for _, test := range htmlTests {
		output := HTML(test.input)
		if output != test.expected {
			t.Fatalf(Format, test.input, test.expected, output)
		}
	}
}

var htmlTestsAllowing = []Test{
	{`hello<br ><br / ><hr /><hr    >rulers`, `hello<br><br><hr/><hr>rulers`},
	{`<span class="testing" id="testid" name="testname" style="font-color:red;text-size:gigantic;"><p>Span</p></span>`, `<span class="testing" id="testid" name="testname"><p>Span</p></span>`},
	{`<div class="divclass">Div</div><h4><h3>test</h4>invalid</h3><p>test</p>`, `<div class="divclass">Div</div><h4><h3>test</h4>invalid</h3><p>test</p>`},
	{`<p>Some text</p><exotic><iframe>test</iframe><frameset src="testing.html"></frameset>`, `<p>Some text</p>`},
	{`<b>hello world</b>`, `<b>hello world</b>`},
	{`text<p>inside<p onclick='alert()'/>too`, `text<p>inside<p/>too`},
	{`&amp;#x000D;`, `&amp;#x000D;`},
	{`<invalid attr="invalid"<,<p><p><p><p><p>`, `<p><p><p><p>`},
	{"<b><p>Bold </b> Not bold</p>\nAlso not bold.", "<b><p>Bold </b> Not bold</p>\nAlso not bold."},
	{"`FOO&#x000D;ZOO", "`FOO&#13;ZOO"},
	{`<script><!--<script </s`, ``},
	{`<a href="/" alt="Fab.com | Aqua Paper Map 22"" title="Fab.com | Aqua Paper Map 22" - fab.com">test</a>`, `test`},
	{"<p</p>?> or <p id=0</p> or <<</>><ASDF><@$!@£M<<>>>>>>>>>>>>>><>***************aaaaaaaaaaaaaaaaaaaaaaaaaa>", "?&gt; or <p id=\"0&lt;/p\"> or &lt;&lt;&gt;&lt;@$!@£M&lt;&lt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&lt;&gt;***************aaaaaaaaaaaaaaaaaaaaaaaaaa&gt;"},
	{`<p>Some text</p><exotic><iframe><frameset src="testing.html"></frameset>`, `<p>Some text</p>`},
	{"Something<br/>Some more", `Something<br/>Some more`},
	{`<a href="http://www.example.com"?>This is a 'test' of <b>bold</b> &amp; <i>italic</i></a> <br/> invalid markup.</data><alert><script CDATA[:Asdfjk2354115nkjafdgs]>. <div src=">escape;inside script tag"><img src="">`, `This is a &#39;test&#39; of <b>bold</b> &amp; <i>italic</i> <br/> invalid markup.`},
	{"<sender ignore=me>John Smith</sender>", `John Smith`},
	{"<!-- <script src='blah.js' data-rel='fsd'> --> This is text", ` This is text`},
	{"<style>body{background-image:url(http://www.google.com/intl/en/images/logo.gif);}</style>", ``},
	{`&lt;iframe src="" attr=""&gt;`, `&lt;iframe src=&#34;&#34; attr=&#34;&#34;&gt;`},
	{`<IMG """><SCRIPT>alert("XSS")</SCRIPT>">`, `&#34;&gt;`},
	{`<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>`, ``},
	{`<IMG SRC=JaVaScRiPt:alert('XSS')&gt;`, ``},
	{`<IMG SRC="javascript:alert('XSS')" <test`, ``},
	{`&gt & test &lt`, `&gt; &amp; test &lt;`},
	{`<img></IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>`, ``},
	{`<img src="data:text/javascript;alert('alert');">`, ``},
	{`<iframe src=http://... <`, ``},
	{`<img src=javascript:alert(document.cookie)>`, ``},
	{`<?php echo('hello world')>`, ``},
}

func TestHTMLAllowed(t *testing.T) {

	for _, test := range htmlTestsAllowing {
		output, err := HTMLAllowing(test.input)
		if err != nil {
			t.Fatalf(Format, test.input, test.expected, output, err)
		}
		if output != test.expected {
			t.Fatalf(Format, test.input, test.expected, output)
		}
	}
}
