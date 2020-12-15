package rtable

import (
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/esote/dht/core"
)

// RTable stores nodes. RTable is safe for concurrent use.
type RTable interface {
	// Store a node. If the RTable is full, return ErrRTableFull.
	Store(n *core.NodeTriple) error

	// Oldest node in the id's corresponding bucket.
	Oldest(id []byte) (*core.NodeTriple, error)

	// Replace replace the oldest node with n.
	ReplaceOldest(n *core.NodeTriple) error

	// Closest finds at most k closest, unequal nodes to id.
	Closest(id []byte, k int) ([]*core.NodeTriple, error)

	// Close the RTable. All future operations return ErrRtableClosed.
	io.Closer
}

// Standard errors a RTable can give.
var (
	ErrRTableFull   = errors.New("rtable: table full")
	ErrRTableClosed = errors.New("rtable: closed")
)

type rtable struct {
	self    []byte
	buckets [core.NodeIDSize * 8]KBucket
	mu      [core.NodeIDSize * 8]*sync.RWMutex
	state   int32
}

const (
	open int32 = iota
	closed
)

// NewRTable creates a file-based RTable.
func NewRTable(self []byte, k int, dir string) (RTable, error) {
	rt := &rtable{
		self:  self,
		state: open,
	}
	var err error
	for i := range rt.buckets {
		file := filepath.Join(dir, bucketFilename(i))
		rt.buckets[i], err = NewKBucket(file, k)
		if err != nil {
			return nil, err
		}
	}
	for i := range rt.mu {
		rt.mu[i] = new(sync.RWMutex)
	}
	return rt, nil
}

func (rt *rtable) Store(n *core.NodeTriple) error {
	if atomic.LoadInt32(&rt.state) == closed {
		return ErrRTableClosed
	}

	index := rt.bucketIndex(n.ID)
	bucket := rt.buckets[index]

	rt.mu[index].Lock()
	defer rt.mu[index].Unlock()

	err := bucket.Store(n)
	if err == ErrKBucketFull {
		err = ErrRTableFull
	}
	return err
}

func (rt *rtable) Oldest(id []byte) (*core.NodeTriple, error) {
	if atomic.LoadInt32(&rt.state) == closed {
		return nil, ErrRTableClosed
	}

	index := rt.bucketIndex(id)
	bucket := rt.buckets[index]

	rt.mu[index].RLock()
	defer rt.mu[index].RUnlock()

	return bucket.Oldest()
}

func (rt *rtable) ReplaceOldest(n *core.NodeTriple) error {
	if atomic.LoadInt32(&rt.state) == closed {
		return ErrRTableClosed
	}

	index := rt.bucketIndex(n.ID)
	bucket := rt.buckets[index]

	rt.mu[index].Lock()
	defer rt.mu[index].Unlock()

	oldest, err := bucket.Oldest()
	if err != nil {
		return err
	}
	if err = bucket.Remove(oldest.ID); err != nil {
		return err
	}
	return bucket.Store(n)
}

func (rt *rtable) Closest(id []byte, k int) ([]*core.NodeTriple, error) {
	if atomic.LoadInt32(&rt.state) == closed {
		return nil, ErrRTableClosed
	}

	var err error
	sorted := make([]*core.NodeTriple, 0, k)
	dist := rt.bucketIndex(id)

	for _, mu := range rt.mu {
		mu.RLock()
	}
	defer func() {
		for _, mu := range rt.mu {
			mu.RUnlock()
		}
	}()

	sorted, err = rt.buckets[dist].Append(sorted, k)
	if err != nil {
		return nil, err
	}
	for i := 1; (dist-i >= 0 || dist+i < len(rt.buckets)) && len(sorted) < k; i++ {
		if dist-i >= 0 {
			sorted, err = rt.buckets[dist-i].Append(sorted, k-len(sorted))
			if err != nil {
				return nil, err
			}
		}
		if dist+i < len(rt.buckets) {
			sorted, err = rt.buckets[dist+i].Append(sorted, k-len(sorted))
			if err != nil {
				return nil, err
			}
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		// Larger LCP means closer to id.
		return core.LCP(id, sorted[i].ID) > core.LCP(id, sorted[j].ID)
	})
	return sorted, nil
}

func (rt *rtable) Close() (err error) {
	if !atomic.CompareAndSwapInt32(&rt.state, open, closed) {
		return ErrRTableClosed
	}
	// TODO: acquire mutexes, don't want to close in the middle of another
	// operation

	for _, kb := range rt.buckets {
		if err2 := kb.Close(); err == nil {
			err = err2
		}
	}
	return
}

func (rt *rtable) bucketIndex(id []byte) int {
	return core.LCP(rt.self, id)
}

func bucketFilename(i int) string {
	return "kb" + strconv.Itoa(i) + ".db"
}
