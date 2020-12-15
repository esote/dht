package rtable

import (
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

// KBucket stores nodes in an LRU cache. KBucket is not safe for concurrent use.
type KBucket interface {
	// Load node by ID. If no node exists with that ID in the bucket, return
	// ErrKBucketNotFound.
	Load(id []byte) (*core.NodeTriple, error)

	// Store or update node. If the bucket is full, return ErrKBucketFull.
	Store(n *core.NodeTriple) error

	// Load oldest node in bucket.
	Oldest() (*core.NodeTriple, error)

	// Remove node by ID.
	Remove(id []byte) error

	// Append bucket contents to slice s, in order of most recent first,
	// until s is at most length n.
	Append(s []*core.NodeTriple, n int) ([]*core.NodeTriple, error)

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
	st map[string]*sql.Stmt
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
		st: make(map[string]*sql.Stmt),
	}

	if err = kb.load(); err != nil {
		_ = kb.Close()
		return nil, err
	}

	kb.st["truncate"], err = kb.db.Prepare(`DELETE FROM "kb"`)
	if err != nil {
		_ = kb.Close()
		return nil, err
	}

	kb.st["insert"], err = kb.db.Prepare(`
INSERT INTO "kb" ("index", "data")
VALUES (?, ?)`)
	if err != nil {
		_ = kb.Close()
		return nil, err
	}

	return kb, nil
}

func (kb *kbucket) Load(id []byte) (*core.NodeTriple, error) {
	if e, ok := kb.m[string(id)]; ok {
		return e.Value.(*core.NodeTriple), nil
	}
	return nil, ErrKBucketNotExist
}

func (kb *kbucket) Store(n *core.NodeTriple) error {
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

func (kb *kbucket) Oldest() (*core.NodeTriple, error) {
	if kb.l.Len() == 0 {
		return nil, ErrKBucketEmpty
	}
	return kb.l.Front().Value.(*core.NodeTriple), nil
}

func (kb *kbucket) Remove(id []byte) error {
	if e, ok := kb.m[string(id)]; ok {
		kb.l.Remove(e)
		delete(kb.m, string(id))
		return kb.sync()
	}
	return ErrKBucketNotExist
}

func (kb *kbucket) Append(s []*core.NodeTriple, n int) ([]*core.NodeTriple, error) {
	for e := kb.l.Back(); e != nil && n > 0; e = e.Prev() {
		s = append(s, e.Value.(*core.NodeTriple))
		n--
	}
	return s, nil
}

func (kb *kbucket) Close() error {
	var err error
	for _, stmt := range kb.st {
		if err2 := stmt.Close(); err == nil {
			err = err2
		}
	}
	if err2 := kb.db.Close(); err == nil {
		err = err2
	}
	return err
}

func (kb *kbucket) sync() error {
	return util.Transact(kb.db, func(tx *sql.Tx) (err error) {
		if _, err = tx.Stmt(kb.st["truncate"]).Exec(); err != nil {
			return err
		}
		insert := tx.Stmt(kb.st["insert"])
		data := make([]byte, core.NodeTripleSize)
		for e, i := kb.l.Back(), 0; e != nil; e, i = e.Prev(), i+1 {
			n := e.Value.(*core.NodeTriple)
			if err = n.MarshalSlice(data); err != nil {
				return err
			}
			if _, err = insert.Exec(i, data); err != nil {
				return err
			}
		}
		return nil
	})
}

func (kb *kbucket) load() error {
	const qCreate = `
CREATE TABLE IF NOT EXISTS "kb" (
	"index" INTEGER PRIMARY KEY,
	"data" BLOB NOT NULL
)`
	const qSelect = `SELECT "data" FROM "kb" ORDER BY "index"`
	const qTruncate = `DELETE FROM "kb" WHERE "index" > ?`
	return util.Transact(kb.db, func(tx *sql.Tx) (err error) {
		if _, err = tx.Exec(qCreate); err != nil {
			return err
		}
		if _, err = tx.Exec(qTruncate, kb.k); err != nil {
			return err
		}
		rows, err := tx.Query(qSelect)
		if err != nil {
			return err
		}
		defer func() {
			if err2 := rows.Close(); err == nil {
				err = err2
			}
		}()
		for rows.Next() {
			var data []byte
			if err = rows.Scan(&data); err != nil {
				return err
			}
			n := new(core.NodeTriple)
			if err = n.UnmarshalSlice(data); err != nil {
				return err
			}
			kb.m[string(n.ID)] = kb.l.PushBack(n)
		}
		return rows.Err()
	})
}
