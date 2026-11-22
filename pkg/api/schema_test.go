package api

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type visitKey struct {
	t    reflect.Type
	path string
}

type schemaWalker struct {
	root    map[string]any
	visited map[visitKey]bool
	missing []string
}

func resolveSchema(root map[string]any, s any) (map[string]any, bool) {
	return resolveSchemaSeen(root, s, make(map[string]bool))
}

func resolveSchemaSeen(root map[string]any, s any, seenRefs map[string]bool) (map[string]any, bool) {
	m, ok := s.(map[string]any)
	if !ok || m == nil {
		return nil, false
	}
	refVal, ok := m["$ref"].(string)
	if !ok {
		return m, true
	}
	if seenRefs[refVal] {
		return m, true
	}
	seenRefs[refVal] = true

	var target any
	if strings.HasPrefix(refVal, "#/$defs/") {
		name := strings.TrimPrefix(refVal, "#/$defs/")
		if defs, ok := root["$defs"].(map[string]any); ok {
			target = defs[name]
		}
	} else if strings.HasPrefix(refVal, "#/definitions/") {
		name := strings.TrimPrefix(refVal, "#/definitions/")
		if defs, ok := root["definitions"].(map[string]any); ok {
			target = defs[name]
		}
	}
	if target == nil {
		return m, true
	}
	return resolveSchemaSeen(root, target, seenRefs)
}

func isOpensaseStruct(t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return false
	}
	return strings.HasPrefix(t.PkgPath(), "github.com/yuky2020/opensase")
}

func (w *schemaWalker) walkField(t reflect.Type, schema map[string]any, path string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		elemType := t.Elem()
		for elemType.Kind() == reflect.Pointer {
			elemType = elemType.Elem()
		}
		if isOpensaseStruct(elemType) || elemType.Kind() == reflect.Slice || elemType.Kind() == reflect.Array || elemType.Kind() == reflect.Map {
			if itemsRaw, ok := schema["items"]; ok {
				if itemsSchema, ok := resolveSchema(w.root, itemsRaw); ok {
					w.walkField(elemType, itemsSchema, path+"[]")
				}
			}
		}
	case reflect.Map:
		elemType := t.Elem()
		for elemType.Kind() == reflect.Pointer {
			elemType = elemType.Elem()
		}
		if isOpensaseStruct(elemType) || elemType.Kind() == reflect.Slice || elemType.Kind() == reflect.Array || elemType.Kind() == reflect.Map {
			if addPropsRaw, ok := schema["additionalProperties"]; ok {
				if addPropsSchema, ok := resolveSchema(w.root, addPropsRaw); ok {
					w.walkField(elemType, addPropsSchema, path)
				}
			}
		}
	case reflect.Struct:
		if isOpensaseStruct(t) {
			w.walkStruct(t, schema, path)
		}
	}
}

func (w *schemaWalker) walkStruct(t reflect.Type, schema map[string]any, path string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if !isOpensaseStruct(t) {
		return
	}

	key := visitKey{t: t, path: path}
	if w.visited[key] {
		return
	}
	w.visited[key] = true

	schema, ok := resolveSchema(w.root, schema)
	if !ok || schema == nil {
		return
	}

	props, _ := schema["properties"].(map[string]any)

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() && !f.Anonymous {
			continue
		}

		tag, hasTag := f.Tag.Lookup("json")
		jsonName := ""
		if hasTag {
			jsonName = strings.Split(tag, ",")[0]
		}

		if f.Anonymous && jsonName == "" {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if isOpensaseStruct(ft) {
				w.walkStruct(ft, schema, path)
			}
			continue
		}

		if jsonName == "" || jsonName == "-" {
			continue
		}

		var fieldPath string
		if path == "" {
			fieldPath = jsonName
		} else {
			fieldPath = path + "." + jsonName
		}

		propSchemaRaw, exists := props[jsonName]
		if !exists {
			w.missing = append(w.missing, fieldPath)
			continue
		}

		propSchema, ok := resolveSchema(w.root, propSchemaRaw)
		if !ok || propSchema == nil {
			continue
		}

		w.walkField(f.Type, propSchema, fieldPath)
	}
}

func structJSONFields(t reflect.Type) map[string]bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	fields := make(map[string]bool)
	if t.Kind() != reflect.Struct {
		return fields
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() && !f.Anonymous {
			continue
		}
		tag, hasTag := f.Tag.Lookup("json")
		jsonName := ""
		if hasTag {
			jsonName = strings.Split(tag, ",")[0]
		}
		if f.Anonymous && jsonName == "" {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for k := range structJSONFields(ft) {
					fields[k] = true
				}
			}
			continue
		}
		if jsonName == "" || jsonName == "-" {
			continue
		}
		fields[jsonName] = true
	}
	return fields
}

func TestTenantPolicySchemaCoversFields(t *testing.T) {
	data, err := os.ReadFile("../../docs/schema/tenant-policy.schema.json")
	if err != nil {
		t.Fatalf("reading schema file: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("parsing schema json: %v", err)
	}

	// Fail if the schema root "properties" has a name that is not a json field of TenantPolicy (stale schema).
	tpFields := structJSONFields(reflect.TypeOf(TenantPolicy{}))
	rootProps, ok := root["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing root properties object")
	}
	var stale []string
	for name := range rootProps {
		if !tpFields[name] {
			stale = append(stale, name)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("schema root has stale properties not in TenantPolicy: %s", strings.Join(stale, ", "))
	}

	// Walk reflect.TypeOf(TenantPolicy{}) recursively and collect missing paths.
	w := &schemaWalker{
		root:    root,
		visited: make(map[visitKey]bool),
	}
	w.walkStruct(reflect.TypeOf(TenantPolicy{}), root, "")

	if len(w.missing) > 0 {
		missingSet := make(map[string]bool)
		for _, m := range w.missing {
			missingSet[m] = true
		}
		var sortedMissing []string
		for m := range missingSet {
			sortedMissing = append(sortedMissing, m)
		}
		sort.Strings(sortedMissing)
		t.Errorf("schema missing fields: %s", strings.Join(sortedMissing, ", "))
	}
}
