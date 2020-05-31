package transport

import (
	"bytes"
	"fmt"
)

// numberRange is an inclusive range.
type numberRange struct {
	start uint64
	end   uint64
}

// rangeSet is sorted ranges in ascending order.
type rangeSet []numberRange

func (s rangeSet) largest() uint64 {
	if len(s) > 0 {
		return s[len(s)-1].end
	}
	return 0
}

func (s rangeSet) contains(n uint64) bool {
	left := 0
	right := len(s)
	for left < right {
		mid := left + (right-left)/2
		r := s[mid]
		if n < r.start {
			right = mid
		} else if n <= r.end {
			return true
		} else {
			left = mid + 1
		}
	}
	return false
}

// equals returns true only when range is continuous from start to end.
func (s rangeSet) equals(start, end uint64) bool {
	return len(s) == 1 && s[0].start == start && s[0].end == end
}

// push adds new range [start, end].
func (s *rangeSet) push(start, end uint64) {
	if end < start {
		panic("invalid number range")
	}
	ls := *s
	idx := ls.insertPos(start)
	if idx < len(ls) {
		r := ls[idx]
		if r.start <= start && end <= r.end {
			// [....]
			//  [..]
			return
		}
		if start > r.start {
			// [..]
			//   [..]
			start = r.start
		}
	}
	if idx > 0 && ls[idx-1].end+1 == start {
		// New range is usually continous, can just extend the range
		// [1..2][3..4] => [1..4]
		idx--
		ls[idx].end = end
	} else {
		s.insert(idx, numberRange{start: start, end: end})
		ls = *s
	}
	// Check if the new range can be merged with the following ranges
	cur := &(*s)[idx]
	k := -1
	for i := idx + 1; i < len(ls); i++ {
		if cur.end+1 < ls[i].start {
			break
		}
		k = i
	}
	if k > idx {
		if cur.end <= ls[k].end {
			cur.end = ls[k].end
		}
		// Remove ranges from idx+1 until k
		copy(ls[idx+1:], ls[k+1:])
		*s = ls[:len(ls)-(k-idx)]
	}
}

// insertPos returns the highest position i where s[i-1].end <= n.
func (s rangeSet) insertPos(n uint64) int {
	left := 0
	right := len(s)
	for left < right {
		mid := left + (right-left)/2
		r := s[mid]
		if n < r.start {
			right = mid
		} else if n <= r.end {
			return mid
		} else {
			left = mid + 1
		}
	}
	return left
}

func (s *rangeSet) insert(idx int, r numberRange) {
	ls := append(*s, numberRange{})
	copy(ls[idx+1:], ls[idx:])
	ls[idx] = r
	*s = ls
}

// removeUntil removes all numbers less than or equal to v.
func (s *rangeSet) removeUntil(v uint64) {
	ls := *s
	// Find starting range to keep
	idx := ls.insertPos(v)
	if idx < len(ls) {
		r := &ls[idx]
		if v < r.start {
			// Keep this range
		} else if v < r.end {
			// Narrow this range
			r.start = v + 1
		} else {
			// Delete this range
			idx++
		}
	}
	if idx > 0 {
		copy(ls, ls[idx:])
		*s = ls[:len(ls)-idx]
	}
}

func (s rangeSet) String() string {
	buf := bytes.Buffer{}
	fmt.Fprintf(&buf, "ranges=%d", len(s))
	for _, r := range s {
		fmt.Fprintf(&buf, " [%d,%d]", r.start, r.end)
	}
	return buf.String()
}

// rangeBuffer represents a fragment of data at an offset.
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

// rangeBufferList is a sorted list of data buffer by offset.
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
	fmt.Fprintf(&buf, "ranges=%d", len(s))
	for _, b := range s {
		fmt.Fprintf(&buf, " %s", &b)
	}
	return buf.String()
}
