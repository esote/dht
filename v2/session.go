package dht

import (
	"container/list"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

type SessionManager struct {
	add      chan *Message
	sessions *sessionCache
	handler  SessionHandler
	state    int32
	wg       sync.WaitGroup
}

const (
	open int32 = iota
	closed
)

type SessionHandler interface {
	Handle(ch <-chan *Message, done <-chan struct{})
}

func NewSessionManager(handler SessionHandler) (*SessionManager, error) {
	sm := &SessionManager{
		add:      make(chan *Message, 16384),
		sessions: newSessionCache(1024),
		handler:  handler,
		state:    open,
	}
	sm.wg.Add(1)
	go sm.consume()
	return sm, nil
}

func (sm *SessionManager) Enqueue(msg *Message) (err error) {
	if atomic.LoadInt32(&sm.state) == closed {
		return errors.New("enqueue on closed session manager")
	}
	select {
	case sm.add <- msg:
	default:
		return errors.New("message dropped")
	}
	return nil
}

func (sm *SessionManager) Close() error {
	if !atomic.CompareAndSwapInt32(&sm.state, open, closed) {
		return errors.New("close on closed session manager")
	}
	close(sm.add)
	sm.wg.Wait()
	return sm.sessions.Close()
}

func (sm *SessionManager) consume() {
	defer sm.wg.Done()
	for m := range sm.add {
		_ = sm.sessions.Store(time.Now().Add(3*time.Second).UTC(), m)
	}
}

type session struct {
	C    <-chan *Message
	Done <-chan struct{}

	rpcid string
	exp   time.Time
	ch    chan *Message
	done  chan struct{}
}

type sessionCache struct {
	capacity int
	cache    map[string]*list.Element
	list     *list.List
	mu       sync.Mutex
	state    int32
}

func newSessionCache(capacity int) *sessionCache {
	if capacity <= 0 {
		panic("cache capacity <= 0")
	}
	return &sessionCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element, capacity),
		list:     list.New(),
		state:    open,
	}
}

func (c *sessionCache) Store(exp time.Time, msg *Message) bool {
	if atomic.LoadInt32(&c.state) == closed {
		return false
	}

	rpcid := string(msg.Hdr.RPCID)
	c.mu.Lock()
	defer c.mu.Unlock()

	if item, hit := c.cache[rpcid]; hit {
		s := item.Value.(*session)
		if !s.Expired() {
			s.exp = exp
			s.ch <- msg // TODO: handle when sending blocks
			return true
		}
		c.remove(item)
	} else if len(c.cache) >= c.capacity {
		item := c.list.Back()
		if item == nil {
			panic("session cache list corrupted")
		}
		s := item.Value.(*session)
		if !s.Expired() {
			return false
		}
		c.remove(item)
	}
	s := &session{
		rpcid: rpcid,
		ch:    make(chan *Message),
		done:  make(chan struct{}),
		exp:   exp,
	}
	s.C = s.ch
	s.Done = s.done
	c.cache[rpcid] = c.list.PushFront(s)
	return true
}

func (c *sessionCache) Close() error {
	if !atomic.CompareAndSwapInt32(&c.state, open, closed) {
		return errors.New("close on closed session cache")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.cache {
		e.Value.(*session).Close()
		c.remove(e)
	}
	c.cache = nil
	c.list = nil
	return nil
}

func (c *sessionCache) remove(item *list.Element) {
	item.Value.(*session).Close()
	delete(c.cache, item.Value.(*session).rpcid)
	c.list.Remove(item)
}

func (s *session) Expired() bool {
	return s.exp.UTC().After(time.Now().UTC())
}

func (s *session) Close() {
	s.done <- struct{}{} // TODO: handle block
	close(s.done)
	close(s.ch)
}
