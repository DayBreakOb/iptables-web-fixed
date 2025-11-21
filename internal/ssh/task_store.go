package ssh

import (
	"errors"
	"sync"
)

type TaskStore interface {
	Save(t *Task) error
	Get(id string) (*Task, error)
	List() ([]*Task, error)
}

type MemoryTaskStore struct {
	mu sync.RWMutex
	m  map[string]*Task
}

func NewMemoryTaskStore() *MemoryTaskStore {
	return &MemoryTaskStore{m: map[string]*Task{}}
}

func (s *MemoryTaskStore) Save(t *Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.m[t.ID] = &cp
	return nil
}

func (s *MemoryTaskStore) Get(id string) (*Task, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.m[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *t
	return &cp, nil
}

func (s *MemoryTaskStore) List() ([]*Task, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Task, 0, len(s.m))
	for _, t := range s.m {
		cp := *t
		out = append(out, &cp)
	}
	return out, nil
}

/*
SQLiteStore 示例（可选）：
- 使用 database/sql + sqlite driver
- 表 schema: tasks(id TEXT PRIMARY KEY, status TEXT, host_json TEXT, cmd_json TEXT, result_json TEXT, ts...)
因为你提过未来 PG/MySQL，也建议只实现 TaskStore 接口即可切换。
*/
