package ssh

import (
	"context"
	"sync"
	"time"

	"iptables-web/backend/internal/models"
)

type TaskStatus string

const (
	TaskPending   TaskStatus = "PENDING"
	TaskRunning   TaskStatus = "RUNNING"
	TaskSucceeded TaskStatus = "SUCCEEDED"
	TaskFailed    TaskStatus = "FAILED"
	TaskCanceled  TaskStatus = "CANCELED"
)

type Task struct {
	ID        string
	Host      models.Host
	Command   Command
	Status    TaskStatus
	CreatedAt time.Time
	StartedAt time.Time
	EndedAt   time.Time
	Result    Result
	Retry     int
	MaxRetry  int
}

type RetryPolicy struct {
	MaxRetry int
	Backoff  time.Duration
}

type ExecutorPool struct {
	Workers int
	Store   TaskStore // 可选持久化
	Hooks   Hooks

	wg    sync.WaitGroup
	queue chan *Task
}

func NewExecutorPool(workers int, store TaskStore, hooks Hooks) *ExecutorPool {
	if workers <= 0 {
		workers = 8
	}
	return &ExecutorPool{
		Workers: workers,
		Store:   store,
		Hooks:   hooks,
		queue:   make(chan *Task, workers*4),
	}
}

func (p *ExecutorPool) Start() {
	for i := 0; i < p.Workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

func (p *ExecutorPool) Stop() {
	close(p.queue)
	p.wg.Wait()
}

func (p *ExecutorPool) Submit(t *Task) {
	if p.Store != nil {
		_ = p.Store.Save(t)
	}
	p.queue <- t
}

func (p *ExecutorPool) worker() {
	defer p.wg.Done()
	for t := range p.queue {
		p.runTask(t)
	}
}

func (p *ExecutorPool) runTask(t *Task) {
	t.Status = TaskRunning
	t.StartedAt = time.Now()
	if p.Store != nil {
		_ = p.Store.Save(t)
	}
	if p.Hooks.OnTask != nil {
		p.Hooks.OnTask(*t)
	}

	cli := New(t.Host)
	cli.Hooks = p.Hooks // 继承 hook
	res := cli.Exec(context.Background(), t.Command.Raw,
		WithPTY(t.Command.PTY),
		WithShell(t.Command.Shell),
		WithStdin(t.Command.Stdin),
		WithTimeout(t.Command.Timeout),
	)

	t.Result = res
	t.EndedAt = time.Now()
	if res.Err == nil {
		t.Status = TaskSucceeded
	} else {
		t.Status = TaskFailed
	}

	if p.Store != nil {
		_ = p.Store.Save(t)
	}
	if p.Hooks.OnTask != nil {
		p.Hooks.OnTask(*t)
	}
}

func (p *ExecutorPool) ExecBatch(
	ctx context.Context,
	hosts []models.Host,
	raw string,
	opts ...ExecOption,
) []Result {
	cmd := buildCommand(raw, opts...)

	var (
		mu  sync.Mutex
		out []Result
		wg  sync.WaitGroup
	)

	sem := make(chan struct{}, p.Workers)

	for _, h := range hosts {
		hh := h
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				out = append(out, Result{HostIP: hh.IP, Err: ctx.Err(), Code: -1})
				mu.Unlock()
				return
			}
			defer func() { <-sem }()

			cli := New(hh)
			cli.Hooks = p.Hooks
			res := cli.Exec(ctx, cmd.Raw, opts...)
			mu.Lock()
			out = append(out, res)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}
