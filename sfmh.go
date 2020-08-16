package main

import (
	"container/heap"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	var mu sync.Mutex
	first := 5 // First executions of query should return some data
	query := func(n *Node) []*Node {
		time.Sleep(time.Millisecond)
		// 52% chance to return nothing (must be >50% to be more likely to
		// terminate then run forever)
		mu.Lock()
		skip := first > 0
		if skip {
			first--
		}
		mu.Unlock()
		if !skip && rand.Intn(100) > 52-1 {
			return []*Node{}
		}
		l := rand.Intn(5)
		if skip && l == 0 {
			l = 2
		}
		nodes := make([]*Node, l)
		for i := range nodes {
			nodes[i] = &Node{rand.Intn(255)}
		}
		return nodes
	}
	start := &Node{V: rand.Int()}
	const target = 128
	f, err := Find(start, target, 5, 100, query)
	if err != nil {
		log.Fatal(err)
	}
	timer := time.NewTimer(time.Second)
	select {
	case found := <-f.Done:
		timer.Stop()
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("done, found:", found)
	case <-timer.C:
		fmt.Println("out of time")
		f.Close()
		os.Exit(1)
	}
}

type Node struct {
	V int
}

func (n *Node) Less(m *Node) bool {
	return n.V < m.V
}

func (n *Node) String() string {
	return fmt.Sprint(n.V)
}

type NodeHeap []*Node

func (h NodeHeap) String() string {
	var s strings.Builder
	s.WriteString("[")
	for i := 0; i < h.Len()-1; i++ {
		fmt.Fprintf(&s, "%s, ", h[i])
	}
	if h.Len() > 0 {
		fmt.Fprintf(&s, "%s", h[h.Len()-1])
	}
	s.WriteString("]")
	return s.String()
}

func (h NodeHeap) Len() int           { return len(h) }
func (h NodeHeap) Less(i, j int) bool { return h[i].Less(h[j]) }
func (h NodeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *NodeHeap) Push(x interface{}) {
	*h = append(*h, x.(*Node))
}

func (h *NodeHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

type Query func(n *Node) []*Node

type Finder struct {
	Done <-chan bool

	target  int
	workers int
	max     int
	q       Query
	heap    NodeHeap
	wg      sync.WaitGroup
	mu      sync.Mutex
	cond    *sync.Cond
	quit    chan struct{}
	done    chan bool
	state   int32
	waiting int
}

const (
	open = iota
	closed
)

func Find(start *Node, target, workers, max int, q Query) (*Finder, error) {
	// assumes: start != nil, workers > 0, max > 0, q != nil
	f := &Finder{
		target:  target,
		workers: workers,
		max:     max,
		q:       q,
		heap:    NodeHeap(q(start)),
		quit:    make(chan struct{}, workers),
		done:    make(chan bool, 1),
		state:   open,
	}
	f.cond = sync.NewCond(&f.mu)
	f.Done = f.done
	heap.Init(&f.heap)
	f.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go f.consume(i)
	}
	return f, nil
}

func (f *Finder) Close() error {
	err := f.closeNonblock(false)
	if err == closeOnClose {
		return nil
	}
	return err
}

var closeOnClose = errors.New("close on closed finder")

func (f *Finder) closeNonblock(found bool) error {
	if !atomic.CompareAndSwapInt32(&f.state, open, closed) {
		return closeOnClose
	}
	for i := 0; i < f.workers; i++ {
		f.quit <- struct{}{}
	}
	f.cond.Broadcast()
	go func() {
		f.wg.Wait()
		f.done <- found
	}()
	return nil
}

func (f *Finder) consume(i int) {
	defer f.wg.Done()
	for {
		select {
		case <-f.quit:
			return
		default:
		}
		f.next(i)
	}
}

func (f *Finder) next(i int) {
	f.mu.Lock()
	// if f.heap.Len() == 0 && all workers waiting, then done, else wait
	if f.heap.Len() == 0 {
		f.waiting++
		if f.waiting == f.workers {
			_ = f.closeNonblock(false)
		} else {
			f.cond.Wait()
		}
		f.waiting--
		f.mu.Unlock()
		return
	}
	n := heap.Pop(&f.heap).(*Node)
	fmt.Println("consumed", n)
	if n.V == f.target {
		f.closeNonblock(true)
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()

	nodes := f.q(n)
	if len(nodes) == 0 {
		return
	}

	f.mu.Lock()
	f.add(nodes)
	f.mu.Unlock()
}

// Add nodes to the heap, and remove maximum elements until len(heap) <= max.
func (f *Finder) add(nodes []*Node) {
	/*
		TODO: use min-max heap:

		The time complexity of sorting, removing max m<n (slicing is
		assumed constant), then heapifying is:

			O(n log n + 1 + log n) = O(n log n)

		Using a min-max heap for poping max m<n and heapifying is:

			O(m log n + log n) = O(m log n)

		O(m log n) performs better than O(n log n) for m < n (the
		common case).
	*/
	l := f.heap.Len()
	f.heap = append(f.heap, nodes...)
	if len(f.heap) > f.max {
		sort.Sort(&f.heap)
		f.heap = f.heap[:f.max]
		heap.Init(&f.heap)
	} else {
		heap.Fix(&f.heap, l-1)
	}
	fmt.Println(f.heap)
	// TODO: benchmark signaling vs broadcast (w/ potential to wake workers
	// with nothing to do).
	if len(f.heap) == f.workers {
		f.cond.Broadcast()
	} else {
		for i := min(len(f.heap), f.workers); i > 0; i-- {
			f.cond.Signal()
		}
	}
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
