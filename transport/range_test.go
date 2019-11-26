package transport

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestRangeSetPush(t *testing.T) {
	x := rangeSetTest{t: t}
	x.ls.push(20)
	x.assertSnapshot("size=1 0:[20,20]")
	x.ls.push(21)
	x.assertSnapshot("size=1 0:[21,20]")
	x.ls.push(19)
	x.assertSnapshot("size=1 0:[21,19]")
	x.ls.push(22)
	x.assertSnapshot("size=1 0:[22,19]")
}

func TestRangeSetRemoveUntil(t *testing.T) {
	x := rangeSetTest{
		t: t,
		ls: rangeSet{
			{start: 12, end: 24},
			{start: 0, end: 10},
		},
	}
	x.ls.removeUntil(0)
	x.assertSnapshot("size=2 0:[24,12] 1:[10,1]")
	x.ls.removeUntil(9)
	x.assertSnapshot("size=2 0:[24,12] 1:[10,10]")
	x.ls.removeUntil(10)
	x.assertSnapshot("size=1 0:[24,12]")
	x.ls.removeUntil(24)
	x.assertSnapshot("size=0")
}

func TestRangeSetRandom(t *testing.T) {
	x := rangeSetTest{t: t}
	n := rand.Intn(1000)
	for i := 0; i < n; i++ {
		x.ls.push(uint64(rand.Intn(100)))
		x.assertOrderedAndNoOverlap()
		x.ls.removeUntil(uint64(rand.Intn(100)))
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
			t.t.Fatalf("list is not sorted\nactual: %+v", &t.ls)
		}
		if i > 0 {
			prev := t.ls[i-1]
			if prev.start <= r.end {
				t.t.Fatalf("list is not sorted\nactual: %+v", &t.ls)
			}
		}
	}
}

func (t *rangeSetTest) assertSize(expect int) {
	if len(t.ls) != expect {
		t.t.Fatalf("size does not match:\nexpect: %d\nactual: %+v", expect, t.ls)
	}
}

func (t *rangeSetTest) assertSnapshot(expect string) {
	actual := t.ls.String()
	if actual != expect {
		t.t.Fatalf("snapshot does not match:\nexpect: %s\nactual: %s", expect, actual)
	}
}

func TestRangeBufferInsertPos(t *testing.T) {
	x := rangeBufferListTest{t: t}
	n := rand.Intn(1000)
	for i := 0; i < n; i++ {
		b := &rangeBuffer{
			data:   nil,
			offset: rand.Uint64(),
		}
		idx := x.ls.insertPos(b.offset)
		x.ls.insert(idx, b)
		x.assertSize(i + 1)
		x.assertOrdered()
	}
}

func TestRangeBufferWriteNoOverlap(t *testing.T) {
	data := makeData(15)
	x := rangeBufferListTest{t: t}
	x.ls.write(data[10:15], 10)
	x.assertSnapshot("size=1 0:[10,15)")
	x.ls.write(data[0:4], 0)
	x.assertSnapshot("size=2 0:[0,4) 1:[10,15)")
	x.ls.write(data[7:10], 7)
	x.assertSnapshot("size=3 0:[0,4) 1:[7,10) 2:[10,15)")
	x.ls.write(data[4:7], 4)
	x.assertSnapshot("size=4 0:[0,4) 1:[4,7) 2:[7,10) 3:[10,15)")
	x.assertOrdered()

	read := make([]byte, 20)
	n := x.ls.read(read[:7], 0)
	if n != 7 {
		t.Fatalf("expect read: %d actual: %d", 7, n)
	}
	x.assertSnapshot("size=2 0:[7,10) 1:[10,15)")
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
	x.assertSnapshot("size=1 0:[10,15)")
	n = x.ls.read(read[10:], 10)
	if n != 5 {
		t.Fatalf("expect read: %d actual: %d", 5, n)
	}
	x.assertSize(0)
	if !bytes.Equal(data, read[:15]) {
		t.Fatalf("data does not match:\nexpect: %x\nactual: %x", data, read[:15])
	}
}

func TestRangeBufferPushDataOverlap(t *testing.T) {
	data := makeData(255)
	x := rangeBufferListTest{t: t}
	x.ls.write(data[50:100], 50)
	x.assertSnapshot("size=1 0:[50,100)")
	x.ls.write(data[80:100], 80)
	x.assertSnapshot("size=1 0:[50,100)")
	x.ls.write(data[40:80], 40)
	x.assertSnapshot("size=2 0:[40,50) 1:[50,100)")
	x.ls.write(data[90:120], 90)
	x.assertSnapshot("size=3 0:[40,50) 1:[50,100) 2:[100,120)")
	x.ls.write(data[150:200], 150)
	x.assertSnapshot("size=4 0:[40,50) 1:[50,100) 2:[100,120) 3:[150,200)")
	x.assertOrdered()

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
	x.assertSnapshot("size=1 0:[150,200)")
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

	read, offset := x.ls.pop(10)
	if offset != 0 || !bytes.Equal(data[:10], read) {
		t.Fatalf("data does not match:\nexpect: %x\nactual: %x (offset=%d)", data[:10], read, offset)
	}
	x.assertSnapshot("size=3 0:[10,100) 1:[100,120) 2:[150,180)")
	read, offset = x.ls.pop(150)
	if offset != 10 || !bytes.Equal(data[10:120], read) {
		t.Fatalf("data does not match:\nexpect: %x\nactual: %x (offset=%d)", data[10:120], read, offset)
	}
	x.assertSnapshot("size=1 0:[150,180)")
	read, offset = x.ls.pop(10)
	if offset != 150 || !bytes.Equal(data[150:160], read) {
		t.Fatalf("data does not match:\nexpect: %x\nactual: %x (offset=%d)", data[10:120], read, offset)
	}
	x.assertSnapshot("size=1 0:[160,180)")
}

func BenchmarkRangeBuffer(b *testing.B) {
	b.ReportAllocs()
	ls := rangeBufferList{}
	data := make([]byte, 100)
	for i := 0; i < b.N; i++ {
		ls.write(data, 0)
		ls.read(data, 0)
	}
}

type rangeBufferListTest struct {
	t  *testing.T
	ls rangeBufferList
}

func (t *rangeBufferListTest) assertOrdered() {
	if !isListOrdered(t.ls) {
		t.t.Fatalf("list is not sorted\nactual: %+v", &t.ls)
	}
}

func (t *rangeBufferListTest) assertSize(expect int) {
	ls := t.ls
	if len(ls) != expect {
		t.t.Fatalf("size does not match:\nexpect: %d\nactual: %+v", expect, ls)
	}
}

func (t *rangeBufferListTest) assertSnapshot(expect string) {
	actual := t.ls.String()
	if actual != expect {
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
