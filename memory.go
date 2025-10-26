package traefik_plugin_torblock

import "sync"

type MemoryStore struct {
	data map[string]struct{}
	mu   sync.RWMutex
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data: make(map[string]struct{}),
	}
}

func (m *MemoryStore) Update(list map[string]struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = list
}

func (m *MemoryStore) Contains(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[ip]
	return ok
}

func (m *MemoryStore) Close() error { return nil }
