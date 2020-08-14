package dht

import (
	"bytes"
	"container/list"
	"database/sql"
	"errors"
	"io"
	"net/url"

	"github.com/esote/dht/core"
	"github.com/esote/dht/util"

	// SQLite3 driver.
	_ "github.com/mattn/go-sqlite3"
)

// KBucket stores nodes in an LRU cache.
type KBucket interface {
	// Load node by ID. If no node exists with that ID in the bucket, return
	// ErrKBucketNotFound.
	Load(id *core.ID) (*core.Node, error)

	// Store or update node. If the bucket is full, return ErrKBucketFull.
	Store(n *core.Node) error

	// Load oldest node in bucket.
	Oldest() (*core.Node, error)

	// Remove node by ID.
	Remove(id *core.ID) error

	// Append bucket contents to slice s, in order of most recent first,
	// until s is at most length n.
	Append(s []*core.Node, n int) ([]*core.Node, error)

	// Close the KBucket.
	io.Closer
}

// Standard errors a KBucket can give.
var (
	ErrKBucketNotExist = errors.New("kbucket: no such node")
	ErrKBucketFull     = errors.New("kbucket: bucket full")
	ErrKBucketEmpty    = errors.New("kbucket: bucket empty")
)

type kbucket struct {
	db *sql.DB
	k  int
	l  *list.List
	m  map[core.ID]*list.Element
}

// NewSqlite3KBucket constructs a SQLite3-backed KBucket.
func NewSqlite3KBucket(file string, k int) (KBucket, error) {
	u := &url.URL{
		Scheme: "file",
		Opaque: file,
	}
	query := u.Query()
	query.Set("_secure_delete", "on")
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	// TODO: create kb table
	kb := &kbucket{
		db: db,
		k:  k,
		l:  list.New(),
		m:  make(map[core.ID]*list.Element, k),
	}
	if err = kb.load(); err != nil {
		return nil, err
	}
	return kb, nil
}

func (kb *kbucket) Load(id *core.ID) (*core.Node, error) {
	if id == nil {
		return nil, errors.New("kbucket: id is nil")
	}
	if e, ok := kb.m[*id]; ok {
		return e.Value.(*core.Node), nil
	}
	return nil, ErrKBucketNotExist
}

func (kb *kbucket) Store(n *core.Node) error {
	if n == nil {
		return errors.New("kbucket: n is nil")
	}
	if e, ok := kb.m[n.ID]; ok {
		kb.l.MoveToBack(e)
		return kb.sync()
	}
	if len(kb.m) == kb.k {
		return ErrKBucketFull
	}
	kb.m[n.ID] = kb.l.PushBack(n)
	return kb.sync()
}

func (kb *kbucket) Oldest() (*core.Node, error) {
	if kb.l.Len() == 0 {
		return nil, ErrKBucketEmpty
	}
	return kb.l.Front().Value.(*core.Node), nil
}

func (kb *kbucket) Remove(id *core.ID) error {
	if id == nil {
		return errors.New("kbucket: id is nil")
	}
	if e, ok := kb.m[*id]; ok {
		kb.l.Remove(e)
		delete(kb.m, *id)
		return kb.sync()
	}
	return ErrKBucketNotExist
}

func (kb *kbucket) Append(s []*core.Node, n int) ([]*core.Node, error) {
	for e := kb.l.Back(); e != nil && n > 0; e = e.Prev() {
		s = append(s, e.Value.(*core.Node))
		n--
	}
	return s, nil
}

func (kb *kbucket) Close() error {
	return kb.db.Close()
}

// TODO: put queries in statements
func (kb *kbucket) sync() error {
	return util.Transact(kb.db, func(tx *sql.Tx) (err error) {
		const qTruncate = `DELETE FROM kb`
		const qInsert = `INSERT INTO kb(id, data) VALUES (?, ?)`
		if _, err = tx.Exec(qTruncate); err != nil {
			return err
		}
		var b bytes.Buffer
		for e, i := kb.l.Back(), 0; e != nil; e, i = e.Prev(), i+1 {
			b.Reset()
			e.Value.(*core.Node).Encode(&b)
			if _, err = tx.Exec(qInsert, i, b.Bytes()); err != nil {
				return err
			}
		}
		return nil
	})
}

// TODO: put queries in statements
func (kb *kbucket) load() error {
	return util.Transact(kb.db, func(tx *sql.Tx) error {
		const qSelect = `SELECT data FROM kb ORDER BY id`
		const qTruncate = `DELETE FROM kb WHERE id > ?`
		if _, err := tx.Exec(qTruncate, kb.k); err != nil {
			return err
		}
		rows, err := tx.Query(qSelect, kb.k)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var data []byte
			if err = rows.Scan(&data); err != nil {
				return err
			}
			n, err := core.NewNode(bytes.NewReader(data))
			if err != nil {
				return err
			}
			kb.m[n.ID] = kb.l.PushBack(n)
		}
		return nil
	})
}
