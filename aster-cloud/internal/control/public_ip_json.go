package control

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// This separate parser retains the original controller JSON contract. Public
// inventory bodies and immutable operation results need a bounded 128KiB limit
// and explicit RFC3339 time values; no other endpoint is widened.
// Every declared wire key is exact-case, required unless omitempty, and unique.
// Null is allowed only for explicitly nullable pointers such as preset resources.
func strictPublicIP(raw []byte, target any) bool {
	if len(raw) == 0 || len(raw) > 131072 || !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 12 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] || !walk(depth+1) {
					return false
				}
				seen[s] = true
			}
			end, e := d.Token()
			return e == nil && end == json.Delim('}')
		case json.Delim('['):
			for d.More() {
				if !walk(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim(']')
		}
		_, bad := t.(json.Delim)
		return !bad
	}
	if !walk(0) || d.Decode(new(any)) != io.EOF {
		return false
	}
	if !shapePublicIP(raw, reflect.TypeOf(target).Elem()) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(target) == nil
}
func shapePublicIP(raw []byte, t reflect.Type) bool {
	if t == reflect.TypeOf(time.Time{}) {
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return false
		}
		_, err := time.Parse(time.RFC3339Nano, text)
		return err == nil
	}

	if t.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return true
		}
		return shapePublicIP(raw, t.Elem())
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return false
		}
		allowed := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if tag == "-" {
				continue
			}
			allowed[tag] = true
			v, ok := fields[tag]
			if !ok {
				if strings.Contains(f.Tag.Get("json"), ",omitempty") || strings.Contains(f.Tag.Get("json"), ",omitzero") {
					continue
				}
				return false
			}
			if !shapePublicIP(v, f.Type) {
				return false
			}
		}
		for k := range fields {
			if !allowed[k] {
				return false
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || values == nil {
			return false
		}
		for _, v := range values {
			if !shapePublicIP(v, t.Elem()) {
				return false
			}
		}
	}
	return true
}
