package mapping

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"
)

// PathSegment represents one step in a parsed JSON path.
type PathSegment struct {
	Name    string // property name, or "" if array wildcard
	IsArray bool   // true for [*]
}

// ParsePath parses a JSON path like "$.dependencies[*].vulns[*]" or "$.results[*]".
func ParsePath(path string) ([]PathSegment, error) {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, "$.") {
		path = path[2:]
	} else if strings.HasPrefix(path, "$") {
		path = path[1:]
	}

	parts := strings.Split(path, ".")
	var segments []PathSegment

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		if strings.HasSuffix(p, "[*]") {
			name := strings.TrimSuffix(p, "[*]")
			if name != "" {
				segments = append(segments, PathSegment{Name: name, IsArray: false})
			}
			segments = append(segments, PathSegment{Name: "", IsArray: true})
		} else {
			segments = append(segments, PathSegment{Name: p, IsArray: false})
		}
	}

	if len(segments) == 0 {
		return nil, errors.New("empty path selector")
	}
	return segments, nil
}

// StreamItem yields one record with its parent and top-level doc properties.
type StreamItem struct {
	Rec    map[string]any
	Parent map[string]any
	Doc    map[string]any
}

// StreamRecords streams matching records from an io.Reader according to the path selector.
func StreamRecords(ctx context.Context, r io.Reader, recordsPath string, parentVar string, maxRecords, maxDepth int) iter.Seq2[StreamItem, error] {
	return func(yield func(StreamItem, error) bool) {
		segments, err := ParsePath(recordsPath)
		if err != nil {
			yield(StreamItem{}, fmt.Errorf("invalid records path: %w", err))
			return
		}

		dec := json.NewDecoder(r)

		// Expect opening delimiter
		tok, err := dec.Token()
		if err != nil {
			yield(StreamItem{}, fmt.Errorf("reading root token: %w", err))
			return
		}

		doc := make(map[string]any)
		recordCount := 0

		// Check if root is array (direct array of findings)
		if tok == json.Delim('[') {
			for dec.More() {
				if ctx.Err() != nil {
					return
				}
				if recordCount >= maxRecords {
					yield(StreamItem{}, fmt.Errorf("exceeded maxRecords limit %d", maxRecords))
					return
				}
				var rec map[string]any
				if err := dec.Decode(&rec); err != nil {
					if !yield(StreamItem{}, fmt.Errorf("decode record: %w", err)) {
						return
					}
					continue
				}
				recordCount++
				if !yield(StreamItem{Rec: rec, Parent: map[string]any{}, Doc: doc}, nil) {
					return
				}
			}
			return
		}

		if tok != json.Delim('{') {
			yield(StreamItem{}, fmt.Errorf("expected '{' or '[', got %v", tok))
			return
		}

		// Helper to stream through matching segments
		streamWalk(ctx, dec, segments, 0, doc, map[string]any{}, parentVar, &recordCount, maxRecords, maxDepth, yield)
	}
}

func streamWalk(
	ctx context.Context,
	dec *json.Decoder,
	segments []PathSegment,
	segIdx int,
	doc map[string]any,
	parent map[string]any,
	parentVar string,
	count *int,
	maxRecords, maxDepth int,
	yield func(StreamItem, error) bool,
) bool {
	if segIdx >= len(segments) {
		return true
	}

	targetSeg := segments[segIdx]

	if !targetSeg.IsArray {
		// We are inside an object, looking for targetSeg.Name
		for dec.More() {
			if ctx.Err() != nil {
				return false
			}
			t, err := dec.Token()
			if err != nil {
				return yield(StreamItem{}, err)
			}
			key, ok := t.(string)
			if !ok {
				continue
			}

			if key == targetSeg.Name {
				// Matched property
				if segIdx+1 < len(segments) && segments[segIdx+1].IsArray {
					// Next is array opening
					tok, err := dec.Token()
					if err != nil {
						return yield(StreamItem{}, err)
					}
					if tok != json.Delim('[') {
						var skip any
						_ = dec.Decode(&skip)
						continue
					}

					// If this is the final array before records:
					if segIdx+2 >= len(segments) {
						// Each element is rec
						for dec.More() {
							if ctx.Err() != nil {
								return false
							}
							if *count >= maxRecords {
								return yield(StreamItem{}, fmt.Errorf("exceeded maxRecords limit %d", maxRecords))
							}
							var rec map[string]any
							if err := dec.Decode(&rec); err != nil {
								if !yield(StreamItem{}, fmt.Errorf("decode record: %w", err)) {
									return false
								}
								continue
							}
							*count++
							if !yield(StreamItem{Rec: rec, Parent: parent, Doc: doc}, nil) {
								return false
							}
						}
						// Closing ']'
						_, _ = dec.Token()
					} else {
						// Nested array (e.g. dependencies[*])
						for dec.More() {
							if ctx.Err() != nil {
								return false
							}
							var depObj map[string]any
							if err := dec.Decode(&depObj); err != nil {
								if !yield(StreamItem{}, fmt.Errorf("decode parent: %w", err)) {
									return false
								}
								continue
							}
							// Recurse into nested path inside depObj
							subPath := segments[segIdx+2:]
							if !streamFromMemoryObj(ctx, depObj, subPath, doc, depObj, parentVar, count, maxRecords, yield) {
								return false
							}
						}
						// Closing ']'
						_, _ = dec.Token()
					}
				} else {
					// Next is non-array property, recurse
					tok, err := dec.Token()
					if err != nil {
						return yield(StreamItem{}, err)
					}
					if tok == json.Delim('{') {
						if !streamWalk(ctx, dec, segments, segIdx+1, doc, parent, parentVar, count, maxRecords, maxDepth, yield) {
							return false
						}
					} else {
						var skip any
						_ = dec.Decode(&skip)
					}
				}
			} else {
				// Top-level scalar property
				if segIdx == 0 {
					var val any
					if err := dec.Decode(&val); err == nil {
						doc[key] = val
					}
				} else {
					var skip any
					_ = dec.Decode(&skip)
				}
			}
		}
		// Read closing '}'
		_, _ = dec.Token()
	}

	return true
}

func streamFromMemoryObj(
	ctx context.Context,
	obj map[string]any,
	segments []PathSegment,
	doc map[string]any,
	parent map[string]any,
	parentVar string,
	count *int,
	maxRecords int,
	yield func(StreamItem, error) bool,
) bool {
	if len(segments) == 0 {
		return true
	}

	target := segments[0]
	val, exists := obj[target.Name]
	if !exists {
		return true
	}

	if len(segments) > 1 && segments[1].IsArray {
		list, ok := val.([]any)
		if !ok {
			return true
		}
		for _, item := range list {
			if ctx.Err() != nil {
				return false
			}
			if *count >= maxRecords {
				return yield(StreamItem{}, fmt.Errorf("exceeded maxRecords limit %d", maxRecords))
			}
			rec, ok := item.(map[string]any)
			if !ok {
				continue
			}
			*count++
			if !yield(StreamItem{Rec: rec, Parent: parent, Doc: doc}, nil) {
				return false
			}
		}
	}
	return true
}
