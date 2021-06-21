package transport

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestRangeSetPush(t *testing.T) {
	x := rangeSetTest{t: t}
	data := []struct {
		m, n uint64
		s    string
	}{
		{20, 20, "ranges=1 [20,20]"},
		{21, 21, "ranges=1 [20,21]"},                 // Extend UB
		{19, 19, "ranges=1 [19,21]"},                 // Extend LB
		{21, 22, "ranges=1 [19,22]"},                 // Extend UB with overlap
		{24, 24, "ranges=2 [19,22] [24,24]"},         // Add UB with gap
		{17, 17, "ranges=3 [17,17] [19,22] [24,24]"}, // Add LB with gap
		{25, 27, "ranges=3 [17,17] [19,22] [24,27]"}, // Extend single UB
		{15, 17, "ranges=3 [15,17] [19,22] [24,27]"}, // Extend single LB
		{16, 16, "ranges=3 [15,17] [19,22] [24,27]"}, // Overlap LB
		{19, 21, "ranges=3 [15,17] [19,22] [24,27]"}, // Overlap
		{24, 24, "ranges=3 [15,17] [19,22] [24,27]"}, // Overlap UB
		{17, 18, "ranges=2 [15,22] [24,27]"},         // Join range
		{29, 30, "ranges=3 [15,22] [24,27] [29,30]"},
		{23, 28, "ranges=1 [15,30]"}, // Join two ranges
	}
	for _, d := range data {
		x.ls.push(d.m, d.n)
		x.assertSnapshot(d.s)
		x.assertContain(d.m)
		x.assertContain(d.n)
		x.assertNotContain(14)
		x.assertNotContain(31)
	}
}

func TestRangeSetRemoveUntil(t *testing.T) {
	x := rangeSetTest{t: t}
	x.ls.push(0, 10)
	x.ls.push(12, 24)
	data := []struct {
		n uint64
		s string
	}{
		{0, "ranges=2 [1,10] [12,24]"},
		{9, "ranges=2 [10,10] [12,24]"},
		{10, "ranges=1 [12,24]"},
		{24, "ranges=0"},
	}
	for _, d := range data {
		x.ls.removeUntil(d.n)
		x.assertSnapshot(d.s)
		x.assertNotContain(d.n)
		x.assertNotContain(11)
	}
}

func TestRangeSetRandom(t *testing.T) {
	x := rangeSetTest{t: t}
	n := rand.Intn(1000)
	for i := 0; i < n; i++ {
		start := uint64(rand.Intn(100))
		end := start + uint64(rand.Intn(50))
		x.ls.push(start, end)
		x.assertOrderedAndNoOverlap()
		x.ls.removeUntil(uint64(rand.Intn(200)))
		x.assertOrderedAndNoOverlap()
	}
}

type rangeSetTest struct {
	t  *testing.T
	ls rangeSet
}

func (t *rangeSetTest) assertOrderedAndNoOverlap() {
	for i, r := range t.ls {
		if r.start > r.end {
			t.t.Helper()
			t.t.Fatalf("list is not sorted\nactual: %+v", &t.ls)
		}
		if i > 0 {
			prev := t.ls[i-1]
			if prev.end >= r.start {
				t.t.Helper()
				t.t.Fatalf("list is not sorted\nactual: %+v", &t.ls)
			}
		}
	}
}

func (t *rangeSetTest) assertSnapshot(expect string) {
	actual := t.ls.String()
	if actual != expect {
		t.t.Helper()
		t.t.Fatalf("snapshot does not match:\nexpect: %s\nactual: %s", expect, actual)
	}
}

func (t *rangeSetTest) assertContain(v uint64) {
	if !t.ls.contains(v) {
		t.t.Helper()
		t.t.Fatalf("list does not contain: %v", v)
	}
}

func (t *rangeSetTest) assertNotContain(v uint64) {
	if t.ls.contains(v) {
		t.t.Helper()
		t.t.Fatalf("list does contain: %v", v)
	}
}

func TestRangeBufferInsertPos(t *testing.T) {
	x := rangeBufferListTest{t: t}
	n := rand.Intn(1000)
	min, max := maxUint64, uint64(0)
	for i := 0; i < n; i++ {
		b := rangeBuffer{
			data:   nil,
			offset: rand.Uint64(),
		}
		if max < b.offset {
			max = b.offset
		}
		if b.offset < min {
			min = b.offset
		}
		idx := x.ls.insertPos(b.offset)
		x.ls.insert(idx, b)
		x.assertSize(i+1, max-min)
		x.assertOrdered()
	}
}

func TestRangeBufferWriteNoOverlap(t *testing.T) {
	data := makeData(15)
	x := rangeBufferListTest{t: t}
	x.ls.write(data[10:15], 10)
	x.assertSnapshot("ranges=1 [10,15)")
	x.ls.write(data[0:4], 0)
	x.assertSnapshot("ranges=2 [0,4) [10,15)")
	x.ls.write(data[7:10], 7)
	x.assertSnapshot("ranges=3 [0,4) [7,10) [10,15)")
	x.ls.write(data[4:7], 4)
	x.assertSnapshot("ranges=4 [0,4) [4,7) [7,10) [10,15)")
	x.assertOrdered()

	read := make([]byte, 20)
	n := x.ls.read(read[:7], 0)
	if n != 7 {
		t.Fatalf("expect read: %d actual: %d", 7, n)
	}
	x.assertSnapshot("ranges=2 [7,10) [10,15)")
	n = x.ls.read(read, 6)
	if n != 0 {
		t.Fatalf("expect read: %d actual: %d", 0, n)
	}
	n = x.ls.read(read, 8)
	if n != 0 {
		t.Fatalf("expect read: %d actual: %d", 0, n)
	}
	n = x.ls.read(read[7:10], 7)
	if n != 3 {
		t.Fatalf("expect read: %d actual: %d", 3, n)
	}
	x.assertSnapshot("ranges=1 [10,15)")
	n = x.ls.read(read[10:], 10)
	if n != 5 {
		t.Fatalf("expect read: %d actual: %d", 5, n)
	}
	x.assertSize(0, 0)
	if !bytes.Equal(data, read[:15]) {
		t.Fatalf("data does not match:\nexpect: %x\nactual: %x", data, read[:15])
	}
}

func TestRangeBufferPushDataOverlap(t *testing.T) {
	data := makeData(255)
	x := rangeBufferListTest{t: t}
	x.ls.write(data[50:100], 50)
	x.assertSnapshot("ranges=1 [50,100)")
	x.ls.write(data[80:100], 80)
	x.assertSnapshot("ranges=1 [50,100)")
	x.ls.write(data[40:80], 40)
	x.assertSnapshot("ranges=2 [40,50) [50,100)")
	x.ls.write(data[90:120], 90)
	x.assertSnapshot("ranges=3 [40,50) [50,100) [100,120)")
	x.ls.write(data[150:200], 150)
	x.assertSnapshot("ranges=4 [40,50) [50,100) [100,120) [150,200)")
	x.assertOrdered()
	x.assertSize(4, 160)

	read := make([]byte, len(data))
	n := x.ls.read(read, 150)
	if n != 0 {
		t.Fatalf("expect read: %d actual: %d", 0, n)
	}
	n = x.ls.read(read, 40)
	if n != 80 {
		t.Fatalf("expect read: %d actual: %d", 80, n)
	}
	read = read[:n]
	if !bytes.Equal(data[40:120], read) {
		t.Fatalf("data does not match:\nexpect: %x\nactual: %x", data[40:120], read)
	}
	x.assertSnapshot("ranges=1 [150,200)")
}

func TestRangeBufferWrite(t *testing.T) {
	x := rangeBufferListTest{t: t}
	data := makeData(1000)
	var prev string
	for i := 0; i < 100; i++ {
		offset := rand.Intn(len(data) - 1)
		end := offset + 1 + rand.Intn(len(data)-1-offset)
		x.ls.write(data[offset:end], uint64(offset))
		if !isListOrdered(x.ls) {
			t.Fatalf("expect sorted: off=%d len=%d end=%d\nactual: %+v\nprev:   %s",
				offset, end-offset, end, &x.ls, prev)
		}
		prev = x.ls.String()
	}
}

func TestRangeBufferPop(t *testing.T) {
	x := rangeBufferListTest{t: t}
	data := makeData(200)
	x.ls.write(data[:10], 0)
	x.ls.write(data[10:100], 10)
	x.ls.write(data[100:120], 100)
	x.ls.write(data[150:180], 150)

	read, offset := x.ls.pop(2)
	if offset != 0 || !bytes.Equal(data[:2], read) {
		t.Fatalf("data does not match:\nexpect: %x\nactual: %x (offset=%d)", data[:2], read, offset)
	}
	x.assertSnapshot("ranges=4 [2,10) [10,100) [100,120) [150,180)")
	read, offset = x.ls.pop(8)
	if offset != 2 || !bytes.Equal(data[2:10], read) {
		t.Fatalf("data does not match:\nexpect: %x\nactual: %x (offset=%d)", data[2:10], read, offset)
	}
	x.assertSnapshot("ranges=3 [10,100) [100,120) [150,180)")
	read, offset = x.ls.pop(150)
	if offset != 10 || !bytes.Equal(data[10:120], read) {
		t.Fatalf("data does not match:\nexpect: %x\nactual: %x (offset=%d)", data[10:120], read, offset)
	}
	x.assertSnapshot("ranges=1 [150,180)")
	read, offset = x.ls.pop(10)
	if offset != 150 || !bytes.Equal(data[150:160], read) {
		t.Fatalf("data does not match:\nexpect: %x\nactual: %x (offset=%d)", data[10:120], read, offset)
	}
	x.assertSnapshot("ranges=1 [160,180)")
}

func BenchmarkRangeBuffer(b *testing.B) {
	b.ReportAllocs()
	ls := rangeBufferList{}
	data := make([]byte, 1000)
	for i := 0; i < b.N; i++ {
		ls.write(data, 0)
		ls.write(data, uint64(len(data)))
		ls.read(data, 0)
		ls.read(data, uint64(len(data)))
	}
}

type rangeBufferListTest struct {
	t  *testing.T
	ls rangeBufferList
}

func (t *rangeBufferListTest) assertOrdered() {
	if !isListOrdered(t.ls) {
		t.t.Helper()
		t.t.Fatalf("list is not sorted\nactual: %+v", &t.ls)
	}
}

func (t *rangeBufferListTest) assertSize(length int, size uint64) {
	ls := t.ls
	if len(ls) != length {
		t.t.Helper()
		t.t.Fatalf("length does not match:\nexpect: %d\nactual: %+v", length, ls)
	}
	if ls.size() != size {
		t.t.Helper()
		t.t.Fatalf("size does not match:\nexpect: %d\nactual: %d %+v", size, ls.size(), ls)
	}
}

func (t *rangeBufferListTest) assertSnapshot(expect string) {
	actual := t.ls.String()
	if actual != expect {
		t.t.Helper()
		t.t.Fatalf("snapshot does not match:\nexpect: %s\nactual: %s", expect, actual)
	}
}

func isListOrdered(ls rangeBufferList) bool {
	for i, b := range ls {
		if i < len(ls)-1 {
			next := ls[i+1]
			if b.offset+uint64(len(b.data)) > next.offset {
				return false
			}
		}
		for i := range b.data {
			if b.data[i] != uint8(b.offset+uint64(i)) {
				return false
			}
		}
	}
	return true
}

func makeData(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = uint8(i)
	}
	return data
}
