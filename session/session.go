package session

import (
	"container/list"
	"errors"
	"sync"
	"time"
)

// Manager is a cache of expiring sessions with registered handlers.
type Manager struct {
	hf HandlerFunc

	capacity int
	cache    map[interface{}]*list.Element
	list     *list.List

	open bool
	mu   sync.Mutex
}

// Handler contains details on how to route values.
type Handler struct {
	// Ch is used to send recieved values.
	Ch chan<- interface{}

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
		cache:    make(map[interface{}]*list.Element, capacity),
		list:     list.New(),
		open:     true,
	}
}

// Register a custom handler for a session, which will be used in favor of the
// default handler until the session expires.
func (m *Manager) Register(key interface{}, exp time.Time, handler Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.open {
		return errors.New("manager: register on closed manager")
	}
	if item, hit := m.cache[key]; hit {
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
		ch:   handler.Ch,
		done: handler.Done,
		key:  key,
		exp:  exp,
	}
	m.cache[key] = m.list.PushFront(s)
	return nil
}

// Enqueue a value and route it to a handler.
func (m *Manager) Enqueue(key, value interface{}, exp time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.open {
		return errors.New("manager: enqueue on closed manager")
	}
	if item, hit := m.cache[key]; hit {
		s := item.Value.(*session)
		if !s.expired() {
			// extend session expiration time
			s.push(exp, value)
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
		ch:   handler.Ch,
		done: handler.Done,
		key:  key,
		exp:  exp,
	}
	s.push(exp, value)
	m.cache[key] = m.list.PushFront(s)
	return nil
}

// Remove a session by its key from the cache.
func (m *Manager) Remove(key interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.open {
		return errors.New("manager: remove on closed manager")
	}
	item, hit := m.cache[key]
	if !hit {
		return errors.New("manager: session with key does not exist")
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
	delete(m.cache, item.Value.(*session).key)
	m.list.Remove(item)
}

type session struct {
	ch   chan<- interface{}
	done chan<- struct{}

	key interface{}
	exp time.Time
}

func (s *session) expired() bool {
	return s.exp.Before(time.Now().UTC())
}

func (s *session) push(exp time.Time, value interface{}) {
	s.exp = exp // XXX: only update exp if sending on ch succeeds?
	select {
	case s.ch <- value:
	default:
	}
}

func (s *session) close() {
	s.exp = time.Unix(0, 0)
	s.done <- struct{}{}
}
