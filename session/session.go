package session

import (
	"container/list"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/esote/dht/core"
)

// MessageCloser is a message which may need to be closed.
type MessageCloser struct {
	*core.Message
	io.Closer
}

// Manager is a cache of expiring sessions with registered handlers.
type Manager struct {
	hf HandlerFunc

	capacity int
	cache    map[string]*list.Element
	list     *list.List

	open bool
	mu   sync.Mutex
}

// Handler contains details on how to route values.
type Handler struct {
	// Ch is used to send recieved values.
	Ch chan<- *MessageCloser

	// Done is used to indicate a session has expired or was otherwise
	// closed.
	Done chan<- struct{}
}

// HandlerFunc returns fresh handlers.
type HandlerFunc func() *Handler

// NewManager constructs a manager with a default handler hf and cache capacity.
func NewManager(capacity int, hf HandlerFunc) *Manager {
	return &Manager{
		hf:       hf,
		capacity: capacity,
		cache:    make(map[string]*list.Element, capacity),
		list:     list.New(),
		open:     true,
	}
}

// Register a custom handler for a session, which will be used in favor of the
// default handler until the session expires.
func (m *Manager) Register(rpcid string, exp time.Time, handler *Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.open {
		return errors.New("manager: register on closed manager")
	}
	if item, hit := m.cache[rpcid]; hit {
		s := item.Value.(*session)
		if !s.expired() {
			return errors.New("manager: register on existing session")
		}
		m.remove(item)
	} else if len(m.cache) >= m.capacity {
		item := m.list.Back()
		if item == nil {
			panic("manager: session cache list corrupted")
		}
		s := item.Value.(*session)
		if !s.expired() {
			return errors.New("manager: cache full")
		}
		m.remove(item)
	}
	s := &session{
		ch:    handler.Ch,
		done:  handler.Done,
		rpcid: rpcid,
		exp:   exp,
	}
	m.cache[rpcid] = m.list.PushFront(s)
	return nil
}

// Enqueue a value and route it to a handler.
func (m *Manager) Enqueue(msg *MessageCloser) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.open {
		return errors.New("manager: enqueue on closed manager")
	}
	rpcid := string(msg.Hdr.RPCID)
	if item, hit := m.cache[rpcid]; hit {
		s := item.Value.(*session)
		if !s.expired() {
			// extends session expiration time
			s.push(msg)
			return nil
		}
		m.remove(item)
	} else if len(m.cache) >= m.capacity {
		item := m.list.Back()
		if item == nil {
			panic("manager: session cache list corrupted")
		}
		s := item.Value.(*session)
		if !s.expired() {
			return errors.New("manager: cache full")
		}
		m.remove(item)
	}
	handler := m.hf()
	// Add new session
	s := &session{
		ch:    handler.Ch,
		done:  handler.Done,
		rpcid: rpcid,
	}
	s.push(msg)
	m.cache[rpcid] = m.list.PushFront(s)
	return nil
}

// Remove a session by its rpcid from the cache.
func (m *Manager) Remove(rpcid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.open {
		return errors.New("manager: remove on closed manager")
	}
	item, hit := m.cache[rpcid]
	if !hit {
		return errors.New("manager: session with rpcid does not exist")
	}
	m.remove(item)
	return nil
}

// Close the manager. All stored sessions will also be closed.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.open {
		return errors.New("manager: close on closed manager")
	}
	m.open = false

	for _, item := range m.cache {
		m.remove(item)
	}
	m.cache = nil
	m.list = nil
	return nil
}

func (m *Manager) remove(item *list.Element) {
	item.Value.(*session).close()
	delete(m.cache, item.Value.(*session).rpcid)
	m.list.Remove(item)
}

type session struct {
	ch   chan<- *MessageCloser
	done chan<- struct{}

	rpcid string
	exp   time.Time
}

func (s *session) expired() bool {
	return s.exp.Before(time.Now().UTC())
}

func (s *session) push(msg *MessageCloser) {
	s.exp = time.Unix(int64(msg.Hdr.Time), 0)
	select {
	case s.ch <- msg:
	default:
	}
}

func (s *session) close() {
	s.exp = time.Unix(0, 0)
	s.done <- struct{}{}
	// TODO: loop thru ch and close msgs
}
