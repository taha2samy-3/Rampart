package ingest

import "io"

// A report may hold a NUL byte, raw or as the JSON escape \u0000 (a scanner copying a binary string, or a hostile
// file). PostgreSQL stores neither in text or jsonb, so one such record made the whole merge fail with HTTP 500.
// scrubNUL replaces them in the stream, keeping the length so nothing shifts: 0x00 becomes a space, \u0000 becomes
// � (the replacement character).
type nulScrubber struct {
	r    io.Reader
	hold []byte // the end of the last read that may be the start of an escape, kept for the next read
}

func scrubNUL(r io.Reader) io.Reader { return &nulScrubber{r: r} }

var (
	nulEscape      = []byte{'\\', 'u', '0', '0', '0', '0'}
	nulReplacement = []byte{'\\', 'u', 'f', 'f', 'f', 'd'}
)

func (s *nulScrubber) Read(p []byte) (int, error) {
	if len(p) < len(nulEscape) {
		return 0, io.ErrShortBuffer
	}
	n := copy(p, s.hold)
	s.hold = s.hold[:0]
	m, err := s.r.Read(p[n:])
	n += m
	b := p[:n]
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			b[i] = ' '
		}
	}
	for i := 0; i+len(nulEscape) <= len(b); i++ {
		if b[i] == '\\' && string(b[i:i+len(nulEscape)]) == string(nulEscape) {
			copy(b[i:], nulReplacement)
			i += len(nulEscape) - 1
		}
	}
	if err == nil {
		// Hold back a tail that could still become an escape when the next bytes arrive.
		for k := len(nulEscape) - 1; k >= 1; k-- {
			if len(b) >= k && string(b[len(b)-k:]) == string(nulEscape[:k]) {
				s.hold = append(s.hold, b[len(b)-k:]...)
				n -= k
				break
			}
		}
	}
	return n, err
}
