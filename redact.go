package main

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/rehearsedai/cfgredact"
	"go.yaml.in/yaml/v3"
)

// secretRE is the cfgredact default secret rule. cfgredact does not export
// its compiled form, and the split-pair pass needs it.
var secretRE = regexp.MustCompile(cfgredact.DefaultPattern)

// docSepRE matches a YAML document separator line. cfgredact and the YAML
// parser read one document, so each document is redacted alone.
var docSepRE = regexp.MustCompile(`(?m)^---[ \t]*\r?\n`)

// piSuffixRE matches one status line that Pi adds after tool output. The
// line would make JSON or YAML output fail to parse.
var piSuffixRE = regexp.MustCompile(`\n\n(\[Showing [^\n]*\]|Command exited with code \d+|Command aborted|` +
	`Command timed out after [^\n]*|Command terminated without an exit code)$`)

// tokenREs match secrets by their shape. They run on all output, because
// output that is not pure JSON or YAML can hold secrets too. Each one has
// a literal prefix, which lets regexp skip fast to candidates. One regexp
// with alternation has no literal prefix and is several times slower.
var tokenREs = []*regexp.Regexp{
	regexp.MustCompile(`dckr_pat_[A-Za-z0-9_-]+`),
	regexp.MustCompile(`sk_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`hf_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{30,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{30,}`),
	regexp.MustCompile(`xox[abpr]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9+/=_-]{20,}`),
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
}

// keyREs match the value next to a secret key name in text. They are the
// floor under the parsers: they also work on text that no parser accepts,
// such as JSON that Pi cut at 50 KB. The group "value" is hidden.
//
// shortcut: they miss YAML block scalars, JSON objects under a secret key,
// and JSON escaped more than once. Add rules when real output needs them.
var keyREs = func() []*regexp.Regexp {
	const (
		key = `(?:` + cfgredact.DefaultPattern + `)`
		// jv is the content of a JSON string, and yv is a YAML or env value
		// up to the end of the line.
		jv = `(?P<value>(?:[^"\\\n]|\\.)*)`
		yv = `(?P<value>[^\s|>][^\n]*?)[ \t]*$`
		js = `[^"\\\n]*`
	)
	return []*regexp.Regexp{
		// {"password": "x"}
		regexp.MustCompile(`"` + js + key + js + `"\s*:\s*"` + jv + `"`),
		// {"name": "API_KEY", "value": "x"}
		regexp.MustCompile(`"name"\s*:\s*"` + js + key + js + `"\s*,\s*"value"\s*:\s*"` + jv + `"`),
		// {"name": "env[1].name", "value": "API_KEY"}, {"name": "env[1].value", "value": "x"}
		regexp.MustCompile(`"name"\s*:\s*"` + js + `\.name"\s*,\s*"value"\s*:\s*"` + js + key + js +
			`"\s*\}\s*,\s*\{\s*(?:"forceString"\s*:\s*\w+\s*,\s*)?"name"\s*:\s*"` + js +
			`\.value"\s*,\s*"value"\s*:\s*"` + jv + `"`),
		// {\"password\":\"x\"}, the form inside a JSON string
		regexp.MustCompile(`\\"` + js + key + js + `\\"\s*:\s*\\"(?P<value>[^"\n]*?)\\"`),
		// password: x, export API_KEY=x
		regexp.MustCompile(`(?m)^[ \t]*(?:- |export )?[\w.\-]*` + key + `[\w.\-]*[ \t]*[:=][ \t]*` + yv),
		// - name: API_KEY
		//   value: x
		regexp.MustCompile(`(?m)^[ \t]*-?[ \t]*name:[ \t]*['"]?[^\s'"]*` + key + `[^\s'"]*['"]?[ \t]*\n` +
			`[ \t]*value:[ \t]*` + yv),
		// - name: env[1].name
		//   value: API_KEY
		// - name: env[1].value
		//   value: x
		regexp.MustCompile(`(?m)^[ \t]*-?[ \t]*name:[ \t]*\S*\.name[ \t]*\n[ \t]*value:[ \t]*\S*` + key +
			`\S*[ \t]*\n[ \t]*-[ \t]*(?:forceString:[ \t]*\w+[ \t]*\n[ \t]*)?name:[ \t]*\S*\.value[ \t]*\n` +
			`[ \t]*value:[ \t]*` + yv),
	}
}()

// Redact hides the secrets in one tool output.
func Redact(in string) string {
	body, suffix := splitSuffix(in)
	var b strings.Builder
	for _, s := range segments(body) {
		b.WriteString(redactDoc(s))
	}
	body = hideKeyValues(b.String())
	for _, re := range tokenREs {
		body = re.ReplaceAllLiteralString(body, cfgredact.DefaultMarker)
	}
	return body + suffix
}

// redactDoc runs cfgredact on one document if it is JSON or YAML. It
// returns other text unchanged, because String blanks the whole value when
// plain text names a secret and no parser accepts it.
func redactDoc(doc string) string {
	// A redacted document is encoded again without the line breaks around
	// it. Keep them, so that NDJSON lines stay on separate lines. Leading
	// spaces stay in core, because they can set the YAML indentation.
	core := strings.TrimLeft(doc, "\r\n")
	lead := doc[:len(doc)-len(core)]
	core = strings.TrimRight(core, " \t\r\n")
	trail := doc[len(lead)+len(core):]
	c, ok := parseConfig(core)
	if !ok {
		return doc
	}
	// Only a parse of the whole document can be encoded again. A partial
	// parse would drop the rest. String fails closed on such input.
	if c.whole {
		if hidden, found := hideSplitPairs(c.value); found {
			return lead + encode(cfgredact.Redactor{}.Tree(hidden), c.isJSON) + trail
		}
	}
	return lead + cfgredact.Redactor{}.String(core) + trail
}

// segments cuts body into pieces that each hold one YAML document or one
// JSON value. The parsers and cfgredact read only the first document or
// value of a stream. The pieces joined again are equal to body, and
// separator lines are pieces of their own.
func segments(body string) []string {
	var out []string
	last := 0
	for _, loc := range docSepRE.FindAllStringIndex(body, -1) {
		out = append(out, jsonValues(body[last:loc[0]])...)
		out = append(out, body[loc[0]:loc[1]])
		last = loc[1]
	}
	return append(out, jsonValues(body[last:])...)
}

// jsonValues cuts the JSON values at the start of s, such as NDJSON, at
// the end of each value. The text after the last value is one more piece.
// It returns s as one piece if s does not start with a JSON value.
func jsonValues(s string) []string {
	d := json.NewDecoder(strings.NewReader(s))
	var out []string
	last := int64(0)
	for {
		if err := d.Decode(new(json.RawMessage)); err != nil {
			return append(out, s[last:])
		}
		out = append(out, s[last:d.InputOffset()])
		last = d.InputOffset()
	}
}

// hideKeyValues replaces each match of keyREs with the marker. It keeps
// values that are already hidden, so that the output of cfgredact stays
// the same.
func hideKeyValues(s string) string {
	for _, re := range keyREs {
		v := re.SubexpIndex("value")
		var b strings.Builder
		last := 0
		for _, loc := range re.FindAllStringSubmatchIndex(s, -1) {
			start, end := loc[2*v], loc[2*v+1]
			if start == end || strings.Contains(s[start:end], cfgredact.DefaultMarker) {
				continue
			}
			b.WriteString(s[last:start])
			b.WriteString(cfgredact.DefaultMarker)
			last = end
		}
		b.WriteString(s[last:])
		s = b.String()
	}
	return s
}

// splitSuffix removes the Pi status lines from the end of s. A truncation
// notice can come before an exit-code line, so it removes all of them.
func splitSuffix(s string) (body, suffix string) {
	for {
		loc := piSuffixRE.FindStringIndex(s)
		if loc == nil {
			return s, suffix
		}
		suffix = s[loc[0]:] + suffix
		s = s[:loc[0]]
	}
}

// config is a parsed JSON or YAML document that holds a map or a list.
type config struct {
	value  any
	isJSON bool
	// whole is false when text follows the first document or value.
	whole bool
}

// parseConfig parses s if its first document or value is a map or a list.
// A scalar is plain text, because most text parses as a YAML scalar.
func parseConfig(s string) (config, bool) {
	var c config
	// JSON is also YAML, but the YAML parser is much slower on large output.
	// UseNumber keeps large integers exact when the value is encoded again.
	jd := json.NewDecoder(strings.NewReader(s))
	jd.UseNumber()
	if jd.Decode(&c.value) == nil {
		c.isJSON = true
		c.whole = jd.Decode(new(json.RawMessage)) == io.EOF
	} else {
		yd := yaml.NewDecoder(strings.NewReader(s))
		var v any
		if yd.Decode(&v) != nil {
			return config{}, false
		}
		c.value = v
		c.whole = yd.Decode(new(any)) == io.EOF
	}
	switch c.value.(type) {
	case map[string]any, map[any]any, []any:
		return c, true
	}
	return config{}, false
}

// hideSplitPairs hides Argo CD Helm parameters that hold one secret in two
// entries, such as {name: env[1].name, value: JUPYTER_TOKEN} and
// {name: env[1].value, value: <secret>}. cfgredact cannot connect the two
// entries. It returns a copy of v, and whether it hid a value.
//
// shortcut: this belongs in the walk of cfgredact. Move it there when we
// can send changes to rehearsedai/cfgredact.
func hideSplitPairs(v any) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		out, found := make(map[string]any, len(t)), false
		for k, e := range t {
			var f bool
			out[k], f = hideSplitPairs(e)
			found = found || f
		}
		return out, found
	case []any:
		out, found := make([]any, len(t)), false
		secretValues := map[string]bool{}
		for i, e := range t {
			var f bool
			out[i], f = hideSplitPairs(e)
			found = found || f
			_, name, value := pair(e)
			if prefix, ok := strings.CutSuffix(name, ".name"); ok && secretRE.MatchString(value) {
				secretValues[prefix+".value"] = true
			}
		}
		for _, e := range out {
			// e is a copy from the walk above, so this does not change v.
			if m, name, _ := pair(e); m != nil && secretValues[name] {
				m["value"] = cfgredact.DefaultMarker
				found = true
			}
		}
		return out, found
	}
	return v, false
}

// pair returns v as a map, with its string name and value. It returns a
// nil map for anything that is not a map.
func pair(v any) (m map[string]any, name, value string) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, "", ""
	}
	name, _ = m["name"].(string)
	value, _ = m["value"].(string)
	return m, name, value
}

// encode writes v in the format of the input. It matches the cfgredact
// output: compact JSON without HTML escapes, and YAML with indent 2.
func encode(v any, isJSON bool) string {
	var b strings.Builder
	if isJSON {
		e := json.NewEncoder(&b)
		e.SetEscapeHTML(false)
		_ = e.Encode(v) // v comes from parseConfig and Tree, so Encode cannot fail
		return strings.TrimSuffix(b.String(), "\n")
	}
	e := yaml.NewEncoder(&b)
	e.SetIndent(2)
	_ = e.Encode(v) // v comes from parseConfig and Tree, so Encode cannot fail
	return b.String()
}
