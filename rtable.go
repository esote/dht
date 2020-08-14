package dht

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
	Store(n *core.Node) error

	// Closest finds at most k closest, unequal nodes to id.
	Closest(id *core.ID, k int) ([]*core.Node, error)

	// Close the RTable.
	io.Closer
}

// Ping a node to see if it is online.
type Ping func(n *core.Node) bool

// Standard errors a RTable can give.
var (
	ErrRTableFull = errors.New("rtable: table full")
)

type rtable struct {
	self    *core.ID
	ping    Ping
	buckets [core.IDLen * 8]KBucket
}

// NewSqlite3RTable constructs a SQLite3-backed RTable, with databases stored in
// dir.
func NewSqlite3RTable(self *core.ID, k int, dir string, ping Ping) (RTable, error) {
	rt := &rtable{
		self: self,
		ping: ping,
	}
	var err error
	for i := 0; i < len(rt.buckets); i++ {
		file := filepath.Join(dir, bucketDB(i))
		rt.buckets[i], err = NewSqlite3KBucket(file, k)
		if err != nil {
			return nil, err
		}
	}
	return rt, nil
}

func (rt *rtable) Store(n *core.Node) error {
	if n == nil {
		return errors.New("rtable: n is nil")
	}
	bucket := rt.buckets[rt.bucketIndex(&n.ID)]
	if err := bucket.Store(n); err != ErrKBucketFull {
		return err
	}
	oldest, err := bucket.Oldest()
	if err != nil {
		return err
	}
	if rt.ping(oldest) {
		if err = bucket.Store(oldest); err != nil {
			return err
		}
		return ErrRTableFull
	}
	if err = bucket.Remove(&oldest.ID); err != nil {
		return err
	}
	return bucket.Store(n)
}

func (rt *rtable) Closest(id *core.ID, k int) ([]*core.Node, error) {
	if id == nil {
		return nil, errors.New("id is nil")
	}
	sorted := make([]*core.Node, 0, k)
	dist := rt.bucketIndex(id)
	sorted, err := rt.buckets[dist].Append(sorted, k)
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
		return id.LCP(&sorted[i].ID) < id.LCP(&sorted[j].ID)
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

func (rt *rtable) bucketIndex(id *core.ID) int {
	return rt.self.LCP(id)
}

func bucketDB(i int) string {
	return "kb" + strconv.Itoa(i) + ".db"
}
