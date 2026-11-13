package mapping

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// Standard CEL helper functions for declarative mapping (docs/19 §4).
func celCustomFunctions() []cel.EnvOption {
	return []cel.EnvOption{
		// lowerAscii: "FOO".lowerAscii() -> "foo"
		cel.Function("lowerAscii",
			cel.MemberOverload("string_lower_ascii", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					s, ok := arg.Value().(string)
					if !ok {
						return types.String("")
					}
					return types.String(strings.ToLower(s))
				}),
			),
		),
		// trim: " foo ".trim() -> "foo"
		cel.Function("trim",
			cel.MemberOverload("string_trim", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					s, ok := arg.Value().(string)
					if !ok {
						return types.String("")
					}
					return types.String(strings.TrimSpace(s))
				}),
			),
		),
		// split: "a:b".split(":") -> ["a", "b"]
		cel.Function("split",
			cel.MemberOverload("string_split", []*cel.Type{cel.StringType, cel.StringType}, cel.ListType(cel.StringType),
				cel.BinaryBinding(func(arg1, arg2 ref.Val) ref.Val {
					s, ok1 := arg1.Value().(string)
					sep, ok2 := arg2.Value().(string)
					if !ok1 || !ok2 {
						return types.DefaultTypeAdapter.NativeToValue([]string{})
					}
					parts := strings.Split(s, sep)
					return types.DefaultTypeAdapter.NativeToValue(parts)
				}),
			),
		),
		// regexExtract: regexExtract("CVE-2023-1234", "CVE-\\d{4}-\\d+") -> "CVE-2023-1234"
		cel.Function("regexExtract",
			cel.Overload("regex_extract_func", []*cel.Type{cel.StringType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(func(arg1, arg2 ref.Val) ref.Val {
					text, ok1 := arg1.Value().(string)
					pattern, ok2 := arg2.Value().(string)
					if !ok1 || !ok2 {
						return types.String("")
					}
					re, err := regexp.Compile(pattern)
					if err != nil {
						return types.String("")
					}
					match := re.FindString(text)
					return types.String(match)
				}),
			),
		),
		// parseCvss: extracts numeric score from CVSS vector or score string
		cel.Function("parseCvss",
			cel.Overload("parse_cvss_func", []*cel.Type{cel.StringType}, cel.DoubleType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					s, ok := arg.Value().(string)
					if !ok {
						return types.Double(0.0)
					}
					// Check if numeric directly
					if val, err := strconv.ParseFloat(s, 64); err == nil {
						return types.Double(val)
					}
					// Parse base score regex e.g. /CVSS:3.1/...
					re := regexp.MustCompile(`(?:score[:=]|/)(\d+\.\d+)`)
					m := re.FindStringSubmatch(s)
					if len(m) > 1 {
						if val, err := strconv.ParseFloat(m[1], 64); err == nil {
							return types.Double(val)
						}
					}
					return types.Double(0.0)
				}),
			),
		),
		// toInt: converts string, float or int to int64
		cel.Function("toInt",
			cel.Overload("to_int_func", []*cel.Type{cel.DynType}, cel.IntType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					v := arg.Value()
					switch val := v.(type) {
					case int:
						return types.Int(val)
					case int64:
						return types.Int(val)
					case float64:
						return types.Int(int64(val))
					case string:
						if i, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64); err == nil {
							return types.Int(i)
						}
					}
					return types.Int(0)
				}),
			),
		),
		// firstNonEmpty: returns first non-empty string in list
		cel.Function("firstNonEmpty",
			cel.Overload("first_non_empty_func", []*cel.Type{cel.ListType(cel.StringType)}, cel.StringType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					list, ok := arg.Value().([]string)
					if ok {
						for _, item := range list {
							if strings.TrimSpace(item) != "" {
								return types.String(item)
							}
						}
						return types.String("")
					}
					return types.String("")
				}),
			),
		),
		// sha256: computes hex sha256 digest of string
		cel.Function("sha256",
			cel.Overload("sha256_func", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					s, ok := arg.Value().(string)
					if !ok {
						return types.String("")
					}
					sum := sha256.Sum256([]byte(s))
					return types.String(hex.EncodeToString(sum[:]))
				}),
			),
		),
	}
}

// CompiledMapping holds compiled CEL programs for each field mapping expression.
type CompiledMapping struct {
	pkg          *MappingPackage
	env          *cel.Env
	ruleID       cel.Program
	title        cel.Program
	desc         cel.Program
	severity     cel.Program
	confidence   cel.Program
	vulnIDs      cel.Program
	toolRecordID cel.Program
	remediation  cel.Program
	file         cel.Program
	startLine    cel.Program
	purl         cel.Program
	pkgName      cel.Program
	installedVer cel.Program
	fixedVer     cel.Program
}

// Compile compiles all CEL expressions in the mapping package with cost limits.
func Compile(pkg *MappingPackage) (*CompiledMapping, error) {
	parentVar := "dep"
	if pkg.Spec.Input.Parent != "" {
		parentVar = pkg.Spec.Input.Parent
	}

	opts := []cel.EnvOption{
		cel.Variable("rec", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(parentVar, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("doc", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("ctx", cel.MapType(cel.StringType, cel.DynType)),
	}
	opts = append(opts, celCustomFunctions()...)

	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("mapping: failed to create CEL env: %w", err)
	}

	cm := &CompiledMapping{pkg: pkg, env: env}

	compileField := func(expr string, prog *cel.Program) error {
		if strings.TrimSpace(expr) == "" {
			return nil
		}
		ast, issues := env.Compile(expr)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("compile CEL expression %q: %w", expr, issues.Err())
		}
		p, err := env.Program(ast, cel.CostLimit(50000))
		if err != nil {
			return fmt.Errorf("build CEL program for %q: %w", expr, err)
		}
		*prog = p
		return nil
	}

	m := pkg.Spec.Map
	if err := compileField(m.RuleID, &cm.ruleID); err != nil {
		return nil, err
	}
	if err := compileField(m.Title, &cm.title); err != nil {
		return nil, err
	}
	if err := compileField(m.Description, &cm.desc); err != nil {
		return nil, err
	}
	if err := compileField(m.Severity, &cm.severity); err != nil {
		return nil, err
	}
	if err := compileField(m.Confidence, &cm.confidence); err != nil {
		return nil, err
	}
	if err := compileField(m.VulnIDs, &cm.vulnIDs); err != nil {
		return nil, err
	}
	if err := compileField(m.ToolRecordID, &cm.toolRecordID); err != nil {
		return nil, err
	}
	if err := compileField(m.Remediation, &cm.remediation); err != nil {
		return nil, err
	}
	if err := compileField(m.Location.File, &cm.file); err != nil {
		return nil, err
	}
	if err := compileField(m.Location.StartLine, &cm.startLine); err != nil {
		return nil, err
	}
	if err := compileField(m.Location.Package.Purl, &cm.purl); err != nil {
		return nil, err
	}
	if err := compileField(m.Location.Package.Name, &cm.pkgName); err != nil {
		return nil, err
	}
	if err := compileField(m.Location.Package.InstalledVersion, &cm.installedVer); err != nil {
		return nil, err
	}
	if err := compileField(m.Location.Package.FixedVersion, &cm.fixedVer); err != nil {
		return nil, err
	}

	return cm, nil
}

// EvalString evaluates a CEL program against variables, returning string or empty.
func (cm *CompiledMapping) EvalString(prog cel.Program, vars map[string]any) string {
	if prog == nil {
		return ""
	}
	out, _, err := prog.Eval(vars)
	if err != nil || out == nil {
		return ""
	}
	v := out.Value()
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// EvalStringSlice evaluates a CEL program expecting a list of strings.
func (cm *CompiledMapping) EvalStringSlice(prog cel.Program, vars map[string]any) []string {
	if prog == nil {
		return nil
	}
	out, _, err := prog.Eval(vars)
	if err != nil || out == nil {
		return nil
	}
	if list, ok := out.Value().([]string); ok {
		return list
	}
	if list, ok := out.Value().([]any); ok {
		res := make([]string, len(list))
		for i, v := range list {
			res[i] = fmt.Sprintf("%v", v)
		}
		return res
	}
	return []string{fmt.Sprintf("%v", out.Value())}
}

// EvalInt evaluates a CEL program expecting an integer.
func (cm *CompiledMapping) EvalInt(prog cel.Program, vars map[string]any) int {
	if prog == nil {
		return 0
	}
	out, _, err := prog.Eval(vars)
	if err != nil || out == nil {
		return 0
	}
	switch v := out.Value().(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return 0
}
