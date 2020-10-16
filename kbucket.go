package dht

import (
	"container/list"
	"database/sql"
	"errors"
	"io"
	"net/url"

	"github.com/esote/dht/util"

	// SQLite3 driver.
	_ "github.com/mattn/go-sqlite3"
)

// KBucket stores nodes in an LRU cache.
type KBucket interface {
	// Load node by ID. If no node exists with that ID in the bucket, return
	// ErrKBucketNotFound.
	Load(id NodeID) (*Node, error)

	// Store or update node. If the bucket is full, return ErrKBucketFull.
	Store(n *Node) error

	// Load oldest node in bucket.
	Oldest() (*Node, error)

	// Remove node by ID.
	Remove(id NodeID) error

	// Append bucket contents to slice s, in order of most recent first,
	// until s is at most length n.
	Append(s []*Node, n int) ([]*Node, error)

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
	m  map[string]*list.Element
}

// NewKBucket constructs a SQLite3-backed KBucket.
func NewKBucket(file string, k int) (KBucket, error) {
	u := &url.URL{
		Scheme: "file",
		Opaque: file,
	}
	query := u.Query()
	query.Set("_secure_delete", "on")
	u.RawQuery = query.Encode()

	// TODO: set SQLITE_LIMIT_LENGTH to NodeSize
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}

	// SQLite3 driver doesn't handle concurrency very well.
	db.SetMaxOpenConns(1)

	kb := &kbucket{
		db: db,
		k:  k,
		l:  list.New(),
		m:  make(map[string]*list.Element, k),
	}

	if err = kb.load(); err != nil {
		_ = kb.Close()
		return nil, err
	}
	return kb, nil
}

func (kb *kbucket) Load(id NodeID) (*Node, error) {
	if e, ok := kb.m[string(id)]; ok {
		return e.Value.(*Node), nil
	}
	return nil, ErrKBucketNotExist
}

func (kb *kbucket) Store(n *Node) error {
	if e, ok := kb.m[string(n.ID)]; ok {
		kb.l.MoveToBack(e)
		return kb.sync()
	}
	if len(kb.m) == kb.k {
		return ErrKBucketFull
	}
	kb.m[string(n.ID)] = kb.l.PushBack(n)
	return kb.sync()
}

func (kb *kbucket) Oldest() (*Node, error) {
	if kb.l.Len() == 0 {
		return nil, ErrKBucketEmpty
	}
	return kb.l.Front().Value.(*Node), nil
}

func (kb *kbucket) Remove(id NodeID) error {
	if e, ok := kb.m[string(id)]; ok {
		kb.l.Remove(e)
		delete(kb.m, string(id))
		return kb.sync()
	}
	return ErrKBucketNotExist
}

func (kb *kbucket) Append(s []*Node, n int) ([]*Node, error) {
	for e := kb.l.Back(); e != nil && n > 0; e = e.Prev() {
		s = append(s, e.Value.(*Node))
		n--
	}
	return s, nil
}

func (kb *kbucket) Close() error {
	return kb.db.Close()
}

// TODO: put queries in statements
func (kb *kbucket) sync() error {
	const qTruncate = `DELETE FROM kb`
	const qInsert = `INSERT INTO kb(index, data) VALUES (?, ?)`
	return util.Transact(kb.db, func(tx *sql.Tx) (err error) {
		if _, err = tx.Exec(qTruncate); err != nil {
			return err
		}
		for e, i := kb.l.Back(), 0; e != nil; e, i = e.Prev(), i+1 {
			data, err := e.Value.(*Node).MarshalBinary()
			if err != nil {
				return err
			}
			if _, err = tx.Exec(qInsert, i, data); err != nil {
				return err
			}
		}
		return nil
	})
}

func (kb *kbucket) load() error {
	const qCreate = `
CREATE TABLE IF NOT EXISTS kb (
	index INTEGER PRIMARY KEY,
	data BLOB NOT NULL
)`
	const qSelect = `SELECT data FROM kb ORDER BY index`
	const qTruncate = `DELETE FROM kb WHERE index > ?`
	return util.Transact(kb.db, func(tx *sql.Tx) error {
		if _, err := tx.Exec(qCreate); err != nil {
			return err
		}
		if _, err := tx.Exec(qTruncate, kb.k); err != nil {
			return err
		}
		rows, err := tx.Query(qSelect)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var data []byte
			if err = rows.Scan(&data); err != nil {
				return err
			}
			var n Node
			if err = n.UnmarshalBinary(data); err != nil {
				return err
			}
			kb.m[string(n.ID)] = kb.l.PushBack(n)
		}
		return rows.Err()
	})
}
