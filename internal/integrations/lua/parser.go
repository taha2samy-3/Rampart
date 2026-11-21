package lua

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"

	lua "github.com/yuin/gopher-lua"
	"gopkg.in/yaml.v3"

	"rampart/internal/domain"
	"rampart/internal/integrations"
)

var (
	ErrInvalidScript = errors.New("lua: invalid parser script")
	ErrExecution     = errors.New("lua: script execution error")
)

func init() {
	integrations.LuaParserLoader = func(name string, raw []byte) (integrations.ParserContract, error) {
		p, err := NewLuaParserFromSpec(name, raw)
		if err != nil {
			return nil, err // not a typed nil inside a non-nil interface
		}
		return p, nil
	}
}

// LuaParserSpec defines the configuration for a Lua-based parser.
type LuaParserSpec struct {
	Name        string            `yaml:"name"`
	Version     string            `yaml:"version"`
	Family      string            `yaml:"family"`
	Category    string            `yaml:"category"`
	Description string            `yaml:"description"`
	Script      string            `yaml:"script"`
	Detect      domain.DetectSpec `yaml:"detect"`
}

// LuaParser implements integrations.ParserContract using gopher-lua.
type LuaParser struct {
	spec LuaParserSpec
	desc integrations.Descriptor
}

// NewLuaParserFromSpec creates a new LuaParser from raw YAML or JSON.
func NewLuaParserFromSpec(name string, raw []byte) (*LuaParser, error) {
	var manifest struct {
		Metadata struct {
			Name string `yaml:"name" json:"name"`
		} `yaml:"metadata" json:"metadata"`
		Spec LuaParserSpec `yaml:"spec" json:"spec"`
	}

	// Try YAML first (which is a superset of JSON)
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidScript, err)
	}

	spec := manifest.Spec
	if spec.Name == "" {
		spec.Name = manifest.Metadata.Name
	}
	if spec.Name == "" {
		spec.Name = name
	}
	if spec.Script == "" {
		return nil, fmt.Errorf("%w: script is required", ErrInvalidScript)
	}

	desc := integrations.Descriptor{
		ID:           "lua:" + spec.Name,
		Name:         spec.Name + " (Lua)",
		Kind:         integrations.KindParser,
		Category:     spec.Category,
		Version:      spec.Version,
		SupportLevel: integrations.SupportCommunity,
		Description:  spec.Description,
	}

	return &LuaParser{
		spec: spec,
		desc: desc,
	}, nil
}

func (p *LuaParser) Descriptor() integrations.Descriptor {
	return p.desc
}

func (p *LuaParser) Detect(head []byte, filename string, contentType string) int {
	return p.spec.Detect.Score(head, filename, contentType)
}

func (p *LuaParser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		L := lua.NewState(lua.Options{
			SkipOpenLibs: true, // Sandboxed: standard os/io/debug libraries disabled
		})
		defer L.Close()

		L.SetContext(ctx)

		// Open only safe base modules: base, table, string, math
		for _, lib := range []struct {
			name string
			fn   lua.LGFunction
		}{
			{lua.BaseLibName, lua.OpenBase},
			{lua.TabLibName, lua.OpenTable},
			{lua.StringLibName, lua.OpenString},
			{lua.MathLibName, lua.OpenMath},
		} {
			L.Push(L.NewFunction(lib.fn))
			L.Push(lua.LString(lib.name))
			L.Call(1, 0)
		}

		// Register json library (json.decode, json.encode)
		jsonMod := L.NewTable()
		L.SetField(jsonMod, "decode", L.NewFunction(luaJSONDecode))
		L.SetField(jsonMod, "encode", L.NewFunction(luaJSONEncode))
		L.SetGlobal("json", jsonMod)

		// Read the entire report stream into memory (subject to ParseContext limits)
		data, err := io.ReadAll(r)
		if err != nil {
			yield(domain.RawFinding{}, fmt.Errorf("lua parser read input: %w", err))
			return
		}

		stopped := false
		emitFn := L.NewFunction(func(L *lua.LState) int {
			if stopped {
				return 0
			}
			tbl := L.OptTable(1, nil)
			if tbl == nil {
				return 0
			}

			rf := p.tableToRawFinding(tbl)
			if !yield(rf, nil) {
				stopped = true
				L.RaiseError("iteration aborted")
			}
			return 0
		})

		// Compile and run the Lua script
		if err := L.DoString(p.spec.Script); err != nil {
			if !stopped {
				yield(domain.RawFinding{}, fmt.Errorf("%w: %v", ErrExecution, err))
			}
			return
		}

		// Call the entrypoint function `parse(input, emit)`
		parseFn := L.GetGlobal("parse")
		if parseFn.Type() != lua.LTFunction {
			yield(domain.RawFinding{}, fmt.Errorf("%w: missing 'parse' function", ErrInvalidScript))
			return
		}

		L.Push(parseFn)
		L.Push(lua.LString(string(data)))
		L.Push(emitFn)

		if err := L.PCall(2, 0, nil); err != nil {
			if !stopped && !strings.Contains(err.Error(), "iteration aborted") {
				yield(domain.RawFinding{}, fmt.Errorf("%w: runtime error: %v", ErrExecution, err))
			}
		}
	}
}

func (p *LuaParser) tableToRawFinding(tbl *lua.LTable) domain.RawFinding {
	getString := func(key string) string {
		val := tbl.RawGetString(key)
		if val.Type() == lua.LTString {
			return val.String()
		}
		return ""
	}
	getInt := func(key string) int {
		val := tbl.RawGetString(key)
		if num, ok := val.(lua.LNumber); ok {
			return int(num)
		}
		return 0
	}

	category := domain.FindingCategory(getString("category"))
	if category == "" {
		category = domain.FindingCategory(p.spec.Category)
	}
	if category == "" {
		category = domain.CategorySAST
	}

	scannerFamily := getString("scanner_family")
	if scannerFamily == "" {
		scannerFamily = p.spec.Family
	}

	sevStr := getString("severity")
	severity := domain.ParseSeverity(sevStr)
	if severity == domain.SeverityUnknown {
		severity = domain.SeverityMedium
	}

	rf := domain.RawFinding{
		RuleID:        getString("rule_id"),
		Title:         getString("title"),
		Description:   getString("description"),
		Severity:      severity,
		ToolSeverity:  sevStr,
		Category:      category,
		ScannerFamily: scannerFamily,
		SecretValue:   getString("secret_value"),
	}

	// Code location
	filePath := getString("file")
	if filePath == "" {
		filePath = getString("path")
	}
	line := getInt("line")
	endLine := getInt("end_line")
	snippet := getString("snippet")

	if filePath != "" || line > 0 || snippet != "" {
		rf.Location.Code = &domain.CodeLocation{
			FilePath:  filePath,
			StartLine: line,
			EndLine:   endLine,
			Snippet:   snippet,
		}
	}

	// Package location (SCA)
	purl := getString("purl")
	pkgName := getString("package")
	if purl != "" || pkgName != "" {
		rf.Location.Package = &domain.PackageLocation{
			Purl:             purl,
			ComponentName:    pkgName,
			InstalledVersion: getString("installed_version"),
			FixedVersion:     getString("fixed_version"),
		}
	}

	// Web location (DAST)
	url := getString("url")
	if url != "" {
		rf.Location.Web = &domain.WebLocation{
			NormalizedURL: url,
			Method:        getString("method"),
			Parameter:     getString("param"),
		}
	}

	if rf.Title == "" {
		rf.Title = rf.RuleID
	}
	if rf.RuleID == "" {
		rf.RuleID = rf.Title
	}

	// Parse CVE / VulnIDs
	cve := getString("cve")
	if cve != "" {
		rf.VulnIDs = append(rf.VulnIDs, cve)
	}
	vulnIDsVal := tbl.RawGetString("vuln_ids")
	if vTbl, ok := vulnIDsVal.(*lua.LTable); ok {
		vTbl.ForEach(func(_, val lua.LValue) {
			if str, ok := val.(lua.LString); ok {
				rf.VulnIDs = append(rf.VulnIDs, string(str))
			}
		})
	}

	// Parse CWE list
	cwesVal := tbl.RawGetString("cwes")
	if cwesTbl, ok := cwesVal.(*lua.LTable); ok {
		cwesTbl.ForEach(func(_, val lua.LValue) {
			if num, ok := val.(lua.LNumber); ok {
				rf.CWEs = append(rf.CWEs, int(num))
			}
		})
	}

	if goMap, ok := luaToGo(tbl).(map[string]any); ok && len(goMap) > 0 {
		attrs := make(map[string]any, len(goMap))
		for k, v := range goMap {
			if k != "secret_value" && k != "secret" && k != "Secret" {
				attrs[k] = v
			}
		}
		rf.Attributes = attrs
		if rawBytes, err := json.Marshal(attrs); err == nil {
			rf.RawPayload = rawBytes
		}
	}

	return rf
}

func luaJSONDecode(L *lua.LState) int {
	str := L.CheckString(1)
	var val any
	if err := json.Unmarshal([]byte(str), &val); err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(goToLua(L, val))
	return 1
}

func luaJSONEncode(L *lua.LState) int {
	val := L.CheckAny(1)
	goVal := luaToGo(val)
	data, err := json.Marshal(goVal)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(string(data)))
	return 1
}

func goToLua(L *lua.LState, val any) lua.LValue {
	switch v := val.(type) {
	case nil:
		return lua.LNil
	case bool:
		return lua.LBool(v)
	case float64:
		return lua.LNumber(v)
	case string:
		return lua.LString(v)
	case []any:
		tbl := L.NewTable()
		for i, item := range v {
			tbl.RawSetInt(i+1, goToLua(L, item))
		}
		return tbl
	case map[string]any:
		tbl := L.NewTable()
		for k, item := range v {
			tbl.RawSetString(k, goToLua(L, item))
		}
		return tbl
	default:
		return lua.LString(fmt.Sprintf("%v", v))
	}
}

func luaToGo(val lua.LValue) any {
	switch v := val.(type) {
	case *lua.LNilType:
		return nil
	case lua.LBool:
		return bool(v)
	case lua.LNumber:
		return float64(v)
	case lua.LString:
		return string(v)
	case *lua.LTable:
		// Check if it's an array
		maxN := v.MaxN()
		if maxN > 0 {
			arr := make([]any, 0, maxN)
			for i := 1; i <= maxN; i++ {
				arr = append(arr, luaToGo(v.RawGetInt(i)))
			}
			return arr
		}
		m := make(map[string]any)
		v.ForEach(func(key, val lua.LValue) {
			m[key.String()] = luaToGo(val)
		})
		return m
	default:
		return v.String()
	}
}
