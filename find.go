package dht

import (
	"container/heap"
	"errors"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/esote/dht/core"
)

var errFinderClosed = errors.New("close on closed finder")

// Largest LCP = nearest to target
func lcpCmp(target, x, y []byte) int {
	xd := core.LCP(target, x)
	yd := core.LCP(target, y)
	switch {
	case xd > yd:
		return -1
	case xd < yd:
		return 1
	default:
		return 0
	}
}

type fheap struct {
	arr    []*core.NodeTriple
	target []byte
}

func (h *fheap) Len() int { return len(h.arr) }

func (h *fheap) Less(i, j int) bool {
	return lcpCmp(h.target, h.arr[i].ID, h.arr[j].ID) < 0
}

func (h *fheap) Swap(i, j int) { h.arr[i], h.arr[j] = h.arr[j], h.arr[i] }

func (h *fheap) Push(x interface{}) {
	h.arr = append(h.arr, x.(*core.NodeTriple))
}

func (h *fheap) Pop() interface{} {
	old := h.arr
	n := len(old)
	x := old[n-1]
	h.arr = old[:n-1]
	return x
}

// query an element and return elements found.
type query func(x *core.NodeTriple) []*core.NodeTriple

// findConfig is used to confgure how elements are located.
type findConfig struct {
	Start   []*core.NodeTriple
	Target  []byte
	K       int // keep track of up to K recent elements
	Workers int
	Max     int
	Query   query
}

// finder finds values.
type finder struct {
	Done <-chan []*core.NodeTriple

	workers int
	max     int
	q       query

	// heap actively pulled from for querying elements
	heap *fheap

	// closest n elements contacted
	closest *fheap
	k       int

	wg      sync.WaitGroup
	mu      sync.Mutex
	cond    *sync.Cond
	quit    chan struct{}
	done    chan []*core.NodeTriple
	state   int32
	waiting int
}

// Find values.
func find(cfg *findConfig) (*finder, error) {
	if cfg.K <= 0 {
		cfg.K = 1
	}
	f := &finder{
		workers: cfg.Workers,
		max:     cfg.Max,
		q:       cfg.Query,
		heap: &fheap{
			arr:    make([]*core.NodeTriple, len(cfg.Start), cfg.Max),
			target: cfg.Target,
		},
		closest: &fheap{
			arr:    make([]*core.NodeTriple, len(cfg.Start), cfg.K),
			target: cfg.Target,
		},
		k:     cfg.K,
		quit:  make(chan struct{}, cfg.Workers),
		done:  make(chan []*core.NodeTriple, 1),
		state: open,
	}
	copy(f.heap.arr, cfg.Start)
	copy(f.closest.arr, cfg.Start)
	f.cond = sync.NewCond(&f.mu)
	f.Done = f.done
	heap.Init(f.heap)
	heap.Init(f.closest)
	f.wg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go f.consume()
	}
	return f, nil
}

// Close the finder. Close does not block.
func (f *finder) Close() error {
	err := f.closeNonblock()
	if err == errFinderClosed {
		return nil
	}
	return err
}

func (f *finder) closeNonblock() error {
	if !atomic.CompareAndSwapInt32(&f.state, open, closed) {
		return errFinderClosed
	}
	for i := 0; i < f.workers; i++ {
		f.quit <- struct{}{}
	}
	f.cond.Broadcast()
	go func() {
		f.wg.Wait()
		closest := make([]*core.NodeTriple, 0, f.k)
		for i := 0; i < f.k && f.closest.Len() > 0; i++ {
			closest = append(closest, heap.Pop(f.closest).(*core.NodeTriple))
		}
		f.done <- closest
	}()
	return nil
}

func (f *finder) consume() {
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

func (f *finder) next() {
	f.mu.Lock()
	if f.heap.Len() == 0 {
		f.waiting++
		if f.waiting == f.workers {
			// All workers waiting on an empty heap, not found.
			_ = f.closeNonblock()
		} else {
			f.cond.Wait()
			f.waiting--
		}
		f.mu.Unlock()
		return
	}
	x := heap.Pop(f.heap).(*core.NodeTriple)
	if lcpCmp(f.heap.target, f.heap.target, x.ID) == 0 {
		f.closeNonblock()
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()

	elements := f.q(x)
	if len(elements) == 0 {
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
	pushMany(f.heap, f.max, elements)
	pushMany(f.closest, f.k, elements)
	// TODO: benchmark signaling vs broadcast (w/ potential to wake workers
	// with nothing to do).
	f.cond.Broadcast()
}

func pushMany(h *fheap, max int, elements []*core.NodeTriple) {
	l := h.Len()
	h.arr = append(h.arr, elements...)
	if h.Len() > max {
		sort.Sort(h)
		h.arr = h.arr[:max]
		heap.Init(h)
	} else {
		heap.Fix(h, l-1)
	}
}
