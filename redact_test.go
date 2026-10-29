package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// Argo CD Helm parameters hold one secret in two entries: the env name in
// env[i].name and the secret in env[i].value.
const (
	argoSplitPair = `{"parameters":[{"name":"env[1].name","value":"JUPYTER_TOKEN"},` +
		`{"forceString":true,"name":"env[1].value","value":"s3cr3t"},` +
		`{"name":"env[2].name","value":"MODE"},{"name":"env[2].value","value":"dev"}]}`
	argoSplitPairYAML = "parameters:\n" +
		"  - name: env[1].name\n    value: JUPYTER_TOKEN\n" +
		"  - name: env[1].value\n    value: s3cr3t\n" +
		"  - name: env[2].name\n    value: MODE\n" +
		"  - name: env[2].value\n    value: dev\n"
	argoClean = `{"parameters":[{"name":"env[2].name","value":"MODE"},{"name":"env[2].value","value":"dev"}]}`
)

// The tokens below are fake. They only have the shape of real tokens.
func TestRedact(t *testing.T) {
	const mark = "[redacted]"
	cases := []struct {
		name string
		in   string
		// want is the exact output. When has and lacks are nil, the test
		// compares the output with want.
		want   string
		format string // "json" or "yaml": the output must parse as this format
		has    []string
		lacks  []string
	}{
		{name: "json_secret_key", in: `{"password":"hunter2","user":"a"}`,
			format: "json", has: []string{`"password":"[redacted]"`, `"user":"a"`}, lacks: []string{"hunter2"}},
		{name: "yaml_secret_key", in: "apiKey: abc\nname: x\n",
			format: "yaml", has: []string{mark, "name: x"}, lacks: []string{"abc"}},
		{name: "clean_json_bytes", in: `{"b": 1,  "a": [1, 2]}`, want: `{"b": 1,  "a": [1, 2]}`},
		{name: "clean_yaml_bytes", in: "# c\nb: 1\na: 2\n", want: "# c\nb: 1\na: 2\n"},
		{name: "text_dckr_pat", in: "token is dckr_pat_AbC-123_x end", want: "token is [redacted] end"},
		{name: "mixed_text_json", in: "---\n{\"x\":\"dckr_pat_abc\"}", want: "---\n{\"x\":\"[redacted]\"}"},
		{name: "kubectl_table", in: "NAME   READY\npod-a  1/1\n", want: "NAME   READY\npod-a  1/1\n"},
		{name: "pem_block", in: "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIx\n-----END RSA PRIVATE KEY-----\nb",
			want: "a\n[redacted]\nb"},
		{name: "json_with_exit_code_suffix", in: "{\"token\":\"x\"}\n\nCommand exited with code 1",
			has: []string{`"token":"[redacted]"`, "\n\nCommand exited with code 1"}, lacks: []string{`"x"`}},
		{name: "json_with_truncation_and_exit_code",
			in:    "{\"token\":\"x\"}\n\n[Showing lines 1-1 of 9. Full output: /tmp/o]\n\nCommand exited with code 2",
			has:   []string{`"token":"[redacted]"`, "\n\n[Showing lines 1-1 of 9. Full output: /tmp/o]\n\nCommand exited with code 2"},
			lacks: []string{`"x"`}},
		{name: "truncated_json_masks_tokens", in: `{"a":"dckr_pat_abc",`, want: `{"a":"[redacted]",`},
		{name: "yaml_scalar_is_text", in: "ok", want: "ok"},
		{name: "text_naming_secret_is_kept", in: "rotate the token today", want: "rotate the token today"},
		{name: "empty", in: "", want: ""},
		{name: "token_sk", in: "k sk_0123456789abcdefghijKL z", want: "k [redacted] z"},
		{name: "token_aws", in: "k AKIAABCDEFGHIJKLMNOP z", want: "k [redacted] z"},
		{name: "token_hf", in: "k hf_0123456789abcdefghijKL z", want: "k [redacted] z"},
		{name: "token_gh", in: "k ghp_0123456789abcdefghijklmnopqrstuvwx z", want: "k [redacted] z"},
		{name: "token_github_pat", in: "k github_pat_0123456789abcdefghijklmnop_qrstuv z", want: "k [redacted] z"},
		{name: "token_slack", in: "k xoxb-0123456789-abcdef z", want: "k [redacted] z"},
		{name: "argo_split_pair", in: argoSplitPair, format: "json",
			has:   []string{`{"forceString":true,"name":"env[1].value","value":"[redacted]"}`, `{"name":"env[2].value","value":"dev"}`},
			lacks: []string{"s3cr3t"}},
		{name: "argo_split_pair_yaml", in: argoSplitPairYAML, format: "yaml",
			has:   []string{"name: env[1].value\n    value: '[redacted]'", "value: dev"},
			lacks: []string{"s3cr3t"}},
		{name: "argo_clean_bytes", in: argoClean, want: argoClean},
		{name: "multi_doc_yaml_keeps_clean_docs", in: "kind: A\n---\nkind: Secret\npassword: hunter2\n",
			has: []string{"kind: A\n---\n", "kind: Secret", "[redacted]"}, lacks: []string{"hunter2"}},
		{name: "multi_doc_yaml_split_pair_keeps_later_docs", in: argoSplitPairYAML + "---\nkind: Secret\npassword: hunter2\n",
			has: []string{"value: '[redacted]'", "\n---\n", "kind: Secret"}, lacks: []string{"s3cr3t", "hunter2"}},
		{name: "big_int_survives_reencode",
			in:  `{"id":12345678901234567890,"p":[{"name":"e.name","value":"API_TOKEN"},{"name":"e.value","value":"x"}]}`,
			has: []string{`"id":12345678901234567890`, `{"name":"e.value","value":"[redacted]"}`}},
		{name: "ndjson_each_value", in: "{\"password\":\"a\"}\n{\"user\":\"b\"}\n",
			want: "{\"password\":\"[redacted]\"}\n{\"user\":\"b\"}\n"},
		{name: "ndjson_split_pair_keeps_other_values", in: argoSplitPair + "\n{\"user\":\"b\"}\n",
			has: []string{`"value":"[redacted]"`, "\n{\"user\":\"b\"}\n"}, lacks: []string{"s3cr3t"}},
		{name: "crlf_doc_separator", in: "kind: A\r\n---\r\npassword: x\r\n",
			has: []string{"kind: A\r\n---\r\n", "[redacted]"}, lacks: []string{": x"}},
		{name: "json_with_trailing_junk_hides_secret", in: `{"password":"a"} }`, want: `{"password":"[redacted]"} }`},
		{name: "json_then_text_redacts_each_part", in: "{\"password\":\"p\"}\ntoken dckr_pat_FAKE123\n",
			want: "{\"password\":\"[redacted]\"}\ntoken [redacted]\n"},
		{name: "json_then_yaml_redacts_yaml", in: "{\"a\":1}\npassword: hunter2\n", lacks: []string{"hunter2"}, has: []string{"{\"a\":1}\n"}},
		{name: "split_pair_with_trailing_junk_hides_secret", in: argoSplitPair + " }", lacks: []string{"s3cr3t"}},
		{name: "ndjson_secret_in_later_line_keeps_newline", in: "{\"a\":1}\n{\"password\":\"p2\"}\n",
			want: "{\"a\":1}\n{\"password\":\"[redacted]\"}\n"},
		{name: "redacted_json_keeps_trailing_newline", in: "{\"password\":\"a\"}\n", want: "{\"password\":\"[redacted]\"}\n"},
		{name: "token_jwt", in: "k eyJhbGciOiJIUzI1NiJ9abcdef.x z", want: "k [redacted].x z"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := Redact(c.in)
			if c.has == nil && c.lacks == nil {
				if out != c.want {
					t.Fatalf("got %q, want %q", out, c.want)
				}
				return
			}
			for _, s := range c.has {
				if !strings.Contains(out, s) {
					t.Errorf("output %q does not contain %q", out, s)
				}
			}
			for _, s := range c.lacks {
				if strings.Contains(out, s) {
					t.Errorf("output %q contains %q", out, s)
				}
			}
			switch c.format {
			case "json":
				if !json.Valid([]byte(out)) {
					t.Errorf("output %q is not JSON", out)
				}
			case "yaml":
				var m map[string]any
				if err := yaml.Unmarshal([]byte(out), &m); err != nil || m == nil {
					t.Errorf("output %q is not a YAML map: %v", out, err)
				}
			}
		})
	}
}

func BenchmarkRedact1MB(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; sb.Len() < 1<<20; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"name":"item-%d","token":"value-%d"}`, i, i)
	}
	sb.WriteString("]")
	in := sb.String()
	b.ResetTimer()
	for range b.N {
		Redact(in)
	}
}

// Pi cuts bash and read output to 50 KB, so this is the common size.
func BenchmarkRedact50KBText(b *testing.B) {
	in := strings.Repeat("NAME                          READY   STATUS    RESTARTS   AGE\n", 800)
	for range b.N {
		Redact(in)
	}
}

func TestReadInputCap(t *testing.T) {
	if _, err := readInput(strings.NewReader(strings.Repeat("a", maxInput))); err != nil {
		t.Fatalf("input at the cap: %v", err)
	}
	if _, err := readInput(strings.NewReader(strings.Repeat("a", maxInput+1))); err == nil {
		t.Fatal("input over the cap: want an error, got nil")
	}
}

// TestNoSecretSurvives checks inputs that the parsers do not accept, such
// as JSON that Pi cut at 50 KB. No value FAKE... may stay in the output.
func TestNoSecretSurvives(t *testing.T) {
	inputs := map[string]string{
		"junk_after_json":        `{"a":1} "password":"FAKE01"}`,
		"json_after_junk":        `{"a":1} oops {"password":"FAKE02"}`,
		"json_cut_at_start":      `":"x"},{"name":"env.API_KEY","value":"FAKE03"},{"name":"b","password":"FAKE04"}]}}}`,
		"json_cut_at_end":        `{"items":[{"name":"x","password":"FAKE05"},{"na`,
		"text_then_json":         "200 OK\n{\"password\":\"FAKE06\"}",
		"argo_pair_json_cut":     `x"},{"name":"env[1].name","value":"JUPYTER_TOKEN"},{"forceString":true,"name":"env[1].value","value":"FAKE07"},{"na`,
		"argo_pair_yaml_cut":     "x: \"cut\n  - name: env[1].name\n    value: JUPYTER_TOKEN\n  - forceString: true\n    name: env[1].value\n    value: FAKE08\n",
		"pod_env_json_cut":       `"x"},{"name":"DB_PASSWORD","value":"FAKE09"},{"na`,
		"pod_env_yaml_cut":       "x: \"cut\n    - name: API_KEY\n      value: FAKE10\n",
		"env_lines":              "export API_KEY=FAKE11\nDB_PASSWORD=FAKE12\n",
		"yaml_key_cut":           "x: \"cut\n  password: FAKE13\n",
		"escaped_json_cut":       `{"output":"{\"password\":\"FAKE14\",\"a\":`,
		"json_space_after_colon": `{"a": [{"secretKey": "FAKE15"}, {"b`,
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			if got := Redact(in); strings.Contains(got, "FAKE") {
				t.Errorf("secret survived: %q", got)
			}
		})
	}
}

// TestKeyMaskKeepsCleanText checks that the key mask does not change text
// without a secret key name.
func TestKeyMaskKeepsCleanText(t *testing.T) {
	for _, in := range []string{
		"NAME STATUS\nnode-1 Ready\n",
		"- name: env[1].name\n  value: JUPYTER_TOKEN\nx: \"cut\n",
		`x"},{"name":"replicas","value":"2"},{"na`,
		"user: alice\nmode: dev\nx: \"cut\n",
	} {
		if got := Redact(in); got != in {
			t.Errorf("Redact(%q) = %q, want it unchanged", in, got)
		}
	}
}
