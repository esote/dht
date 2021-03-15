package util

import (
	"database/sql"
	"fmt"
	"io"
)

// Transact runs a function within a transaction, handlng commit and rollback.
func Transact(db *sql.DB, f func(tx *sql.Tx) error) (err error) {
	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		return
	}
	defer func() {
		if r := recover(); r != nil && err == nil {
			err = fmt.Errorf("%v", r)
		}
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = f(tx); err != nil {
		return
	}
	err = tx.Commit()
	return
}

type readCloser struct {
	io.Reader
	io.Closer
}

// JoinReadCloser combines a Reader and Closer to a ReadCloser.
func JoinReadCloser(r io.Reader, c io.Closer) io.ReadCloser {
	return &readCloser{r, c}
}
