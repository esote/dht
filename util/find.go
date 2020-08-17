package util

import (
	"container/heap"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
)

// Compare two values. Returns 0 if a==b, negative if a<b, and positive a>b.
type Compare func(a, b interface{}) int

type fheap struct {
	arr    []interface{}
	target interface{}
	cmp    Compare
}

func (h *fheap) Len() int           { return len(h.arr) }
func (h *fheap) Less(i, j int) bool { return h.cmp(h.arr[i], h.arr[j]) < 0 }
func (h *fheap) Swap(i, j int)      { h.arr[i], h.arr[j] = h.arr[j], h.arr[i] }

func (h *fheap) Push(x interface{}) {
	h.arr = append(h.arr, x)
}

func (h *fheap) Pop() interface{} {
	old := h.arr
	n := len(old)
	x := old[n-1]
	h.arr = old[:n-1]
	return x
}

// Query an element and return elements found.
type Query func(x interface{}) []interface{}

// FindConfig is used to confgure how elements are located in Find.
type FindConfig struct {
	Start   []interface{}
	Target  interface{}
	Workers int
	Max     int
	Cmp     Compare
	Query   Query
}

// Finder finds values.
type Finder struct {
	Done <-chan interface{}

	workers int
	max     int
	q       Query

	heap    *fheap
	wg      sync.WaitGroup
	mu      sync.Mutex
	cond    *sync.Cond
	quit    chan struct{}
	done    chan interface{}
	state   int32
	waiting int
}

const (
	finderOpen = iota
	finderClosed
)

// Find values.
func Find(cfg *FindConfig) (*Finder, error) {
	f := &Finder{
		workers: cfg.Workers,
		max:     cfg.Max,
		q:       cfg.Query,
		heap: &fheap{
			arr:    cfg.Start,
			target: cfg.Target,
			cmp:    cfg.Cmp,
		},
		quit:  make(chan struct{}, cfg.Workers),
		done:  make(chan interface{}, 1),
		state: finderOpen,
	}
	f.cond = sync.NewCond(&f.mu)
	f.Done = f.done
	heap.Init(f.heap)
	f.wg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go f.consume()
	}
	return f, nil
}

var errFinderClosed = errors.New("close on closed finder")

// Close the finder. Close does not block.
func (f *Finder) Close() error {
	err := f.closeNonblock(nil)
	if err == errFinderClosed {
		return nil
	}
	return err
}

func (f *Finder) closeNonblock(x interface{}) error {
	if !atomic.CompareAndSwapInt32(&f.state, finderOpen, finderClosed) {
		return errFinderClosed
	}
	for i := 0; i < f.workers; i++ {
		f.quit <- struct{}{}
	}
	f.cond.Broadcast()
	go func() {
		f.wg.Wait()
		f.done <- x
	}()
	return nil
}

func (f *Finder) consume() {
	defer f.wg.Done()
	for {
		select {
		case <-f.quit:
			return
		default:
		}
		f.next()
	}
}

func (f *Finder) next() {
	f.mu.Lock()
	if f.heap.Len() == 0 {
		f.waiting++
		if f.waiting == f.workers {
			// All workers waiting on an empty heap, not found.
			_ = f.closeNonblock(nil)
		} else {
			f.cond.Wait()
		}
		f.waiting--
		f.mu.Unlock()
		return
	}
	x := heap.Pop(f.heap)
	if f.heap.cmp(x, f.heap.target) == 0 {
		f.closeNonblock(x)
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()

	nodes := f.q(x)
	if len(nodes) == 0 {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	/*
		TODO: use min-max heap:
		The time complexity of sorting, removing max m<n (slicing is
		assumed constant), then heapifying is:

			O(n log n + 1 + log n) = O(n log n)

		Using a min-max heap for poping max m<n and heapifying is:

			O(m log n + log n) = O(m log n)

		O(m log n) performs better than O(n log n) for m < n (the
		common case) and has smaller constants.
	*/
	l := f.heap.Len()
	f.heap.arr = append(f.heap.arr, nodes...)
	if f.heap.Len() > f.max {
		sort.Sort(f.heap)
		f.heap.arr = f.heap.arr[:f.max]
		heap.Init(f.heap)
	} else {
		heap.Fix(f.heap, l-1)
	}
	// TODO: benchmark signaling vs broadcast (w/ potential to wake workers
	// with nothing to do).
	f.cond.Broadcast()
}
