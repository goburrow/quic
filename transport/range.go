package transport

import (
	"bytes"
	"fmt"
)

type numberRange struct {
	start uint64
	end   uint64
}

// rangeSet is sorted ranges in descending order
type rangeSet []numberRange

func (s rangeSet) largest() uint64 {
	if len(s) > 0 {
		return s[0].end
	}
	return 0
}

func (s rangeSet) contains(n uint64) bool {
	for _, r := range s {
		if n > r.end {
			return false
		}
		if n >= r.start {
			return true
		}
	}
	return false
}

func (s *rangeSet) push(n uint64) {
	ls := *s
	for i := range ls {
		r := &ls[i]
		if n > r.end {
			if n == r.end+1 {
				// Extend current range
				r.end = n
				if i > 0 {
					prev := &ls[i-1]
					if prev.start == r.end+1 {
						// Merge two ranges
						prev.start = r.start
						s.remove(i)
					}
				}
			} else {
				// Insert new range
				s.insert(i, &numberRange{start: n, end: n})
			}
			return
		}
		if n >= r.start {
			return
		}
	}
	if len(ls) > 0 {
		prev := &ls[len(ls)-1]
		if prev.start == n+1 {
			prev.start = n
			return
		}
	}
	*s = append(*s, numberRange{start: n, end: n})
}

func (s *rangeSet) insert(idx int, r *numberRange) {
	ls := append(*s, numberRange{})
	copy(ls[idx+1:], ls[idx:])
	ls[idx] = *r
	*s = ls
}

func (s *rangeSet) remove(idx int) {
	ls := *s
	copy(ls[idx:], ls[idx+1:])
	*s = ls[:len(ls)-1]
}

func (s *rangeSet) removeUntil(v uint64) {
	ls := *s
	idx := -1 // Index to remove
	for i := range ls {
		r := &ls[i]
		if r.end <= v {
			idx = i // Remove current range
			break
		}
		if r.start <= v {
			r.start = v + 1
			idx = i + 1 // Remove next range
			break
		}
	}
	if idx >= 0 {
		*s = ls[:idx]
	}
}

func (s rangeSet) String() string {
	buf := bytes.Buffer{}
	fmt.Fprintf(&buf, "size=%d", len(s))
	for i, r := range s {
		fmt.Fprintf(&buf, " %d:[%d,%d]", i, r.end, r.start)
	}
	return buf.String()
}

type rangeBuffer struct {
	data   []byte
	offset uint64
}

func (s *rangeBuffer) String() string {
	return fmt.Sprintf("[%d,%d)", s.offset, s.offset+uint64(len(s.data)))
}

// newRangeBuffer creates a new buffer with a copy of data.
func newRangeBuffer(data []byte, offset uint64) *rangeBuffer {
	var d []byte
	if len(data) > 0 {
		d = make([]byte, len(data))
		copy(d, data)
	}
	return &rangeBuffer{
		data:   d,
		offset: offset,
	}
}

// rangeBufferList is a sorted list.
type rangeBufferList []rangeBuffer

func (s *rangeBufferList) write(data []byte, offset uint64) {
	if len(data) == 0 {
		return
	}
	end := offset + uint64(len(data))
	// Find initial index to check overlap and insert
	idx := s.insertPos(offset)
	i := idx - 1
	if i < 0 {
		i = 0
	}
	for ; i < len(*s); i++ {
		b := &(*s)[i]
		bStart := b.offset
		bEnd := b.offset + uint64(len(b.data))
		if bStart <= offset {
			if end <= bEnd {
				// Fully contained in existing buffer.
				// XXXXXX
				// OOOOOO
				return
			}
			if offset < bEnd {
				// New start overlaps existing buffer.
				// XXXXXX
				//      OOOO
				data = data[bEnd-offset:]
				offset = bEnd
				idx = i + 1
			}
			// Check next buffer
			// XXXXXX
			//       OOOO
		} else {
			if end < bStart {
				// Found the gap to insert
				//     XXXXXX
				// OOOO
				break
			}
			if end <= bEnd {
				// New end overlaps existing buffer.
				//    XXXXXX
				// OOOO
				// OOOOOOOOO
				data = data[:bStart-offset]
				break
			}
			// Split the new buffer
			//   XXXXXX
			// OOOOOOOOO
			b := newRangeBuffer(data[:bStart-offset], offset)
			s.insert(idx, b)
			data = data[bEnd-offset:]
			offset = bEnd
			idx = i + 2
		}
	}
	b := newRangeBuffer(data, offset)
	s.insert(idx, b)
}

func (s *rangeBufferList) read(data []byte, offset uint64) int {
	var i, n int
	for i = 0; i < len(*s); i++ {
		b := &(*s)[i]
		if b.offset != offset {
			break
		}
		k := copy(data[n:], b.data)
		if k == 0 {
			break
		}
		n += k
		if k < len(b.data) {
			b.data = b.data[k:]
			b.offset += uint64(k)
			break
		}
		offset += uint64(k)
	}
	if i > 0 {
		s.shift(i)
	}
	return n
}

// Return first continuous range
func (s *rangeBufferList) pop(max int) ([]byte, uint64) {
	if len(*s) == 0 || max <= 0 {
		return nil, 0
	}
	offset := (*s)[0].offset
	n := 0
	// Peek available bytes
	for _, b := range *s {
		if b.offset != offset+uint64(n) {
			break
		}
		n += len(b.data)
		if n > max {
			n = max
			break
		}
	}
	// No allocation needed if data is the whole first buffer
	if n == len((*s)[0].data) {
		r := (*s)[0]
		s.shift(1)
		return r.data, offset
	}
	b := make([]byte, n)
	n = s.read(b, offset)
	return b[:n], offset
}

func (s *rangeBufferList) insert(idx int, r *rangeBuffer) {
	ls := append(*s, rangeBuffer{})
	copy(ls[idx+1:], ls[idx:])
	ls[idx] = *r
	*s = ls
}

func (s *rangeBufferList) shift(idx int) {
	ls := *s
	n := copy(ls, ls[idx:])
	for i := n; i < len(ls); i++ {
		ls[i] = rangeBuffer{}
	}
	*s = ls[:n]
}

func (s rangeBufferList) insertPos(offset uint64) int {
	left := 0
	right := len(s)
	for left < right {
		mid := left + (right-left)/2
		if offset < s[mid].offset {
			right = mid
		} else {
			left = mid + 1
		}
	}
	return left
}

func (s rangeBufferList) String() string {
	buf := bytes.Buffer{}
	fmt.Fprintf(&buf, "size=%d", len(s))
	for i, b := range s {
		fmt.Fprintf(&buf, " %d:%s", i, &b)
	}
	return buf.String()
}
