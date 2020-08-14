package main

import (
	"container/heap"
	"math/rand"
	"sync"
	"time"
)

type IntHeap []int

func (h IntHeap) Len() int           { return len(h) }
func (h IntHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h IntHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *IntHeap) Push(x interface{}) {
	*h = append(*h, x.(int))
}

func (h *IntHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func QueryNode(sc bool) []int {
	time.Sleep(20 * time.Millisecond)
	// 52% chance to return nothing (must be >50% to be more likely to
	// terminate then run forever)
	if !sc && rand.Intn(100) > 52-1 {
		return []int{}
	}
	n := make([]int, rand.Intn(4))
	for i := range n {
		n[i] = rand.Int()
	}
	return n
}

func Next(sc bool, c int, quit chan<- struct{}, mu *sync.Mutex, h heap.Interface) bool {
	mu.Lock()
	if h.Len() == 0 {
		for i := 0; i < c; i++ {
			quit <- struct{}{}
		}
		mu.Unlock()
		return false
	}
	_ = heap.Pop(h)
	mu.Unlock()

	nodes := QueryNode(sc)
	if len(nodes) == 0 {
		return true
	}

	mu.Lock()
	// TODO: faster to append, h.Pop(y) then heap.Fix(h, y)?
	// TODO: limit size of heap
	for _, y := range nodes {
		heap.Push(h, y)
	}
	mu.Unlock()
	return true
}

func main() {
	h := &IntHeap{rand.Int()}
	heap.Init(h)
	const c = 1
	quit := make(chan struct{}, c)
	defer close(quit)
	var mu sync.Mutex
	Next(true, c, quit, &mu, h)
	var wg sync.WaitGroup
	wg.Add(c)
	for i := 0; i < c; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-quit:
					return
				default:
				}
				Next(false, c, quit, &mu, h)
			}
		}()
	}
	wg.Wait()
}
