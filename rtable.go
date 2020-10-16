package dht

import (
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strconv"
)

// RTable stores nodes. RTable is safe for concurrent use.
type RTable interface {
	// Store a node.
	Store(n *Node) error

	// Oldest node in the id's corresponding bucket.
	Oldest(id NodeID) (*Node, error)

	// Remove node by id.
	Remove(id NodeID) error

	// Closest finds at most k closest, unequal nodes to id.
	Closest(id NodeID, k int) ([]*Node, error)

	// Close the RTable.
	io.Closer
}

// Standard errors a RTable can give.
var (
	ErrRTableFull = errors.New("rtable: table full")
)

type rtable struct {
	self    NodeID
	buckets [NodeIDSize * 8]KBucket
}

func NewRTable(self NodeID, k int, dir string) (RTable, error) {
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

func (rt *rtable) Store(n *Node) error {
	bucket := rt.buckets[rt.bucketIndex(n.ID)]
	err := bucket.Store(n)
	if err == ErrKBucketFull {
		err = ErrRTableFull
	}
	return err
	/*
		if err := bucket.Store(n); err != ErrKBucketFull {
			return err
		}
		oldest, err := bucket.Oldest()
		if err != nil {
			return err
		}
		// TODO: move ping out of rtable?
		if rt.ping(oldest) {
			if err = bucket.Store(oldest); err != nil {
				return err
			}
			return ErrRTableFull
		}
		if err = bucket.Remove(oldest.ID); err != nil {
			return err
		}
		return bucket.Store(n)
	*/
}

func (rt *rtable) Oldest(id NodeID) (*Node, error) {
	bucket := rt.buckets[rt.bucketIndex(id)]
	return bucket.Oldest()
}

func (rt *rtable) Remove(id NodeID) error {
	bucket := rt.buckets[rt.bucketIndex(id)]
	return bucket.Remove(id)
}

func (rt *rtable) Closest(id NodeID, k int) ([]*Node, error) {
	var err error
	sorted := make([]*Node, 0, k)
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
		return id.LCP(sorted[i].ID) < id.LCP(sorted[j].ID)
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

func (rt *rtable) bucketIndex(id NodeID) int {
	return rt.self.LCP(id)
}

func bucketFilename(i int) string {
	return "kb" + strconv.Itoa(i) + ".db"
}
