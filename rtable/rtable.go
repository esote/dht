package rtable

import (
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/esote/dht/core"
)

// RTable stores nodes. RTable is safe for concurrent use.
type RTable interface {
	// Store a node.
	Store(n *core.NodeTriple) error

	// Oldest node in the id's corresponding bucket.
	Oldest(id []byte) (*core.NodeTriple, error)

	// Remove node by id.
	Remove(id []byte) error

	// Closest finds at most k closest, unequal nodes to id.
	Closest(id []byte, k int) ([]*core.NodeTriple, error)

	// Close the RTable.
	io.Closer
}

// Standard errors a RTable can give.
var (
	ErrRTableFull = errors.New("rtable: table full")
)

type rtable struct {
	self    []byte
	buckets [core.NodeIDSize * 8]KBucket
}

func NewRTable(self []byte, k int, dir string) (RTable, error) {
	rt := &rtable{
		self: self,
	}
	var err error
	for i := range rt.buckets {
		file := filepath.Join(dir, bucketFilename(i))
		rt.buckets[i], err = NewKBucket(file, k)
		if err != nil {
			return nil, err
		}
	}
	return rt, nil
}

func (rt *rtable) Store(n *core.NodeTriple) error {
	bucket := rt.buckets[rt.bucketIndex(n.ID)]
	err := bucket.Store(n)
	if err == ErrKBucketFull {
		err = ErrRTableFull
	}
	return err
}

func (rt *rtable) Oldest(id []byte) (*core.NodeTriple, error) {
	bucket := rt.buckets[rt.bucketIndex(id)]
	return bucket.Oldest()
}

func (rt *rtable) Remove(id []byte) error {
	bucket := rt.buckets[rt.bucketIndex(id)]
	return bucket.Remove(id)
}

func (rt *rtable) Closest(id []byte, k int) ([]*core.NodeTriple, error) {
	var err error
	sorted := make([]*core.NodeTriple, 0, k)
	dist := rt.bucketIndex(id)
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
