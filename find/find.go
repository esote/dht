package find

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/esote/dht/core"
	heap "github.com/esote/minmaxheap"
)

const (
	open = iota
	closed
)

type nodeHeap struct {
	arr    []*core.NodeTriple
	target []byte
}

func (h *nodeHeap) Len() int { return len(h.arr) }

func (h *nodeHeap) Less(i, j int) bool {
	return core.LCP(h.target, h.arr[i].ID) > core.LCP(h.target, h.arr[j].ID)
}

func (h *nodeHeap) Swap(i, j int) { h.arr[i], h.arr[j] = h.arr[j], h.arr[i] }

func (h *nodeHeap) Push(x interface{}) {
	h.arr = append(h.arr, x.(*core.NodeTriple))
}

func (h *nodeHeap) Pop() interface{} {
	old := h.arr
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	h.arr = old[:n-1]
	return x
}

type setHeap struct {
	m map[string]bool
	*nodeHeap
}

func (h *setHeap) Push(x interface{}) {
	h.nodeHeap.Push(x)
	h.m[string(x.(*core.NodeTriple).ID)] = true
}

func (h *setHeap) Pop() interface{} {
	x := h.nodeHeap.Pop()
	delete(h.m, string(x.(*core.NodeTriple).ID))
	return x
}

func (h *setHeap) Contains(n *core.NodeTriple) bool {
	return h.m[string(n.ID)]
}

// Config is used to confgure how elements are located.
type Config struct {
	Start  []*core.NodeTriple
	Target []byte

	Workers int

	MaxBacklogSize   int
	MaxReturn        int
	MaxUniqueHistory int

	Query func(x *core.NodeTriple) []*core.NodeTriple
}

// Finder finds values.
type Finder struct {
	// Done is used to send the finder results, or nil if nothing was found.
	Done <-chan []*core.NodeTriple

	workers int
	q       func(x *core.NodeTriple) []*core.NodeTriple

	// heap actively pulled from for querying elements
	heap           *nodeHeap
	maxBacklogSize int

	// closest elements contacted, used to return results and ensure
	// querying of only uncontacted nodes
	closest          *setHeap
	maxReturn        int
	maxUniqueHistory int

	wg      sync.WaitGroup
	mu      sync.Mutex
	cond    *sync.Cond
	quit    chan struct{}
	done    chan []*core.NodeTriple
	state   int32
	waiting int
}

// Find values.
func Find(cfg *Config) (*Finder, error) {
	if len(cfg.Target) != core.NodeIDSize {
		return nil, errors.New("target invalid")
	}
	if cfg.MaxReturn <= 0 {
		cfg.MaxReturn = 1
	}
	if cfg.MaxBacklogSize <= 0 {
		cfg.MaxBacklogSize = 1
	}
	if cfg.MaxUniqueHistory < cfg.MaxReturn || cfg.MaxUniqueHistory < cfg.MaxBacklogSize {
		cfg.MaxUniqueHistory = max(cfg.MaxReturn, cfg.MaxBacklogSize)
	}
	f := &Finder{
		workers: cfg.Workers,
		q:       cfg.Query,
		heap: &nodeHeap{
			arr:    make([]*core.NodeTriple, len(cfg.Start), cfg.MaxBacklogSize),
			target: cfg.Target,
		},
		maxBacklogSize: cfg.MaxBacklogSize,
		closest: &setHeap{
			nodeHeap: &nodeHeap{
				arr:    make([]*core.NodeTriple, len(cfg.Start), cfg.MaxUniqueHistory),
				target: cfg.Target,
			},
			m: make(map[string]bool, cfg.MaxUniqueHistory),
		},
		maxReturn:        cfg.MaxReturn,
		maxUniqueHistory: cfg.MaxUniqueHistory,
		quit:             make(chan struct{}, cfg.Workers),
		done:             make(chan []*core.NodeTriple, 1),
		state:            open,
	}
	copy(f.heap.arr, cfg.Start)
	copy(f.closest.arr, cfg.Start)
	for _, node := range cfg.Start {
		f.closest.m[string(node.ID)] = true
	}
	heap.Init(f.heap)
	heap.Init(f.closest)
	f.cond = sync.NewCond(&f.mu)
	f.Done = f.done
	f.wg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go f.consume()
	}
	return f, nil
}

// Close does not block: receive from Finder.Done to block until the finder
// finishes.
func (f *Finder) Close() error {
	f.closeNonblock()
	return nil
}

func (f *Finder) closeNonblock() {
	if !atomic.CompareAndSwapInt32(&f.state, open, closed) {
		// Finder already closed
		return
	}
	for i := 0; i < f.workers; i++ {
		f.quit <- struct{}{}
	}
	f.cond.Broadcast()
	go func() {
		f.wg.Wait()
		closest := make([]*core.NodeTriple, 0, f.closest.Len())
		for i := 0; i < f.maxReturn && f.closest.Len() > 0; i++ {
			closest = append(closest, heap.PopMin(f.closest).(*core.NodeTriple))
		}
		f.done <- closest
		close(f.done)
	}()
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
			f.closeNonblock()
		} else {
			f.cond.Wait()
			f.waiting--
		}
		f.mu.Unlock()
		return
	}
	x := heap.PopMin(f.heap).(*core.NodeTriple)
	if bytes.Equal(f.heap.target, x.ID) {
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

	// Remove already-contacted (duplicate) nodes
	var i int
	for _, node := range elements {
		if !f.closest.Contains(node) {
			elements[i] = node
			i++
		}
	}
	for j := i; j < len(elements); j++ {
		elements[j] = nil
	}
	elements = elements[:i]

	pushMany(f.heap, f.maxBacklogSize, elements)
	pushMany(f.closest, f.maxUniqueHistory, elements)

	// TODO: benchmark signaling vs broadcast (w/ potential to wake workers
	// with nothing to do).
	f.cond.Broadcast()
}

func pushMany(h heap.Interface, max int, elements []*core.NodeTriple) {
	for _, node := range elements {
		heap.Push(h, node)
	}
	for n := h.Len(); n > max; n-- {
		_ = heap.PopMax(h)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
