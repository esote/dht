package dht

import (
	"bytes"
	"database/sql"
	"errors"
	"io"
	"math"
	"net/url"
	"sync"

	"github.com/esote/dht/core"
	"github.com/esote/dht/util"

	// SQLite3 driver.
	_ "github.com/mattn/go-sqlite3"
)

// Errors which may be returned by a Storer.
var (
	ErrStorerLarge    = errors.New("storer: value too large")      // EFBIG
	ErrStorerQuota    = errors.New("storer: quota exceeded")       // EDQUOT
	ErrStorerExist    = errors.New("storer: value already exists") // EEXIST
	ErrStorerNotExist = errors.New("storer: value does not exist") // ENOENT
)

// Storer stores key-value pairs. Storer is safe for concurrent use.
type Storer interface {
	// Load a value at a certain seek offset and length. Returns the value
	// and its real length.
	//
	// If the returned value satisfies io.Closer, it will be closed by the
	// DHT. If input length is zero, return the rest of the value.
	//
	// If the value does not exist, Load returns ErrStorerNotExist.
	Load(key *core.ID, offset, length uint64) (io.Reader, uint64, error)

	// Store a value.
	//
	// If the value is too large to be supported, or the total storage
	// capacity has been reached, Store returns ErrStorerLarge. If the
	// storer's quota of key-value pairs has been reached, Storer returns
	// ErrStorerQuota. If the value is already stored, Store returns
	// ErrStorerExist.
	Store(key *core.ID, length uint64, value io.Reader) error

	// Delete a value. If the value does not exist, Delete returns
	// ErrStorerNotExist.
	Delete(key *core.ID) error
}

// TODO: file storer

type sqlite3 struct {
	db *sql.DB

	msize  uint64
	mcount uint64
}

var _ Storer = &sqlite3{}

// NewSqlite3Storer creates a Storer which places key-value pairs into a SQLite3
// database.
func NewSqlite3Storer(file string, maxSize, maxCount uint64) (Storer, error) {
	u := &url.URL{
		Scheme: "file",
		Opaque: file,
	}
	query := u.Query()
	query.Set("_secure_delete", "on")
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite3", u.String())
	// TODO: create table
	if err != nil {
		return nil, err
	}
	return &sqlite3{
		db: db,
	}, nil
}

func (s *sqlite3) Load(key *core.ID, offset, length uint64) (io.Reader, uint64, error) {
	if offset == math.MaxUint64 {
		return nil, 0, errors.New("offset too big for sqlite3 storer")
	}
	const qSelect = `SELECT SUBSTR(value, ?, ?) FROM st WHERE key = ?`
	var value []byte
	var row *sql.Row
	if length == 0 {
		row = s.db.QueryRow(qSelect, offset+1, -1, key[:])
	} else {
		row = s.db.QueryRow(qSelect, offset+1, length, key[:])
	}
	if err := row.Scan(&value); err == sql.ErrNoRows {
		return nil, 0, ErrStorerNotExist
	} else if err != nil {
		return nil, 0, err
	}
	return bytes.NewReader(value), uint64(len(value)), nil
}

func (s *sqlite3) Store(key *core.ID, length uint64, value io.Reader) error {
	if length > s.msize {
		return ErrStorerLarge
	}
	return util.Transact(s.db, func(tx *sql.Tx) error {
		const qCount = "SELECT COUNT(key) FROM st"
		const qInsert = "INSERT INTO st(key, value) VALUES (?, ?)"
		var count uint64
		if err := tx.QueryRow(qCount).Scan(&count); err != nil {
			return err
		}
		if count >= s.mcount {
			return ErrStorerQuota
		}
		// XXX: It would be nice if we didn't have to read the entire
		// value into memory. Does sqlite & mattn's sqlite driver
		// support io.Reader-fed values to gradually buffer data into
		// the database, rather than all from memory. Otherwise it's
		// possible to add hack of buffering by appending to the value
		// in the database.
		var b bytes.Buffer
		if _, err := util.CopyN(&b, value, length); err != nil {
			return err
		}
		_, err := tx.Exec(qInsert, key[:], b.Bytes())
		// TODO: ErrStorerExist, when err gives unique primary key error
		return err
	})
}
func (s *sqlite3) Delete(key *core.ID) error {
	const qDelete = "DELETE FROM st WHERE key = ?"
	_, err := s.db.Exec(qDelete, key[:])
	return err
}

type mem struct {
	data  map[core.ID][]byte
	total uint64

	mu sync.Mutex

	msize  uint64
	mcount uint64
}

var _ Storer = &mem{}

// NewMemoryStorer creates a storer which places key-value pairs in memory.
func NewMemoryStorer(maxSize, maxCount uint64) Storer {
	return &mem{
		data:   make(map[core.ID][]byte),
		msize:  maxSize,
		mcount: maxCount,
	}
}

func (s *mem) Load(key *core.ID, offset, length uint64) (io.Reader, uint64, error) {
	if key == nil {
		return nil, 0, errors.New("key is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[*key]
	if !ok {
		return nil, 0, ErrStorerNotExist
	}
	if length == 0 || length > uint64(len(v)) {
		length = uint64(len(v))
	}
	return bytes.NewReader(v[:length]), length, nil
}

func (s *mem) Store(key *core.ID, length uint64, value io.Reader) error {
	if key == nil {
		return errors.New("key is nil")
	}
	if _, ok := s.data[*key]; ok {
		return ErrStorerExist
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total+length > s.msize {
		return ErrStorerLarge
	}
	if uint64(len(s.data))+1 > s.mcount {
		return ErrStorerQuota
	}
	var b bytes.Buffer
	if _, err := util.CopyN(&b, value, length); err != nil {
		return err
	}
	s.total += length
	s.data[*key] = b.Bytes()
	return nil
}

func (s *mem) Delete(key *core.ID) error {
	if key == nil {
		return errors.New("key is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[*key]; !ok {
		return ErrStorerNotExist
	}
	delete(s.data, *key)
	return nil
}
