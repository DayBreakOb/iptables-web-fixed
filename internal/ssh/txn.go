package ssh

import (
	"context"
	"fmt"
)

type Txn struct {
	c      *Client
	v6     bool
	backup string
	active bool
}

func (c *Client) BeginIptablesTxn(ctx context.Context, v6 bool) (*Txn, error) {
	bak, err := c.IptablesSave(v6)
	if err != nil {
		return nil, err
	}
	return &Txn{c: c, v6: v6, backup: bak, active: true}, nil
}

func (t *Txn) Commit() {
	t.active = false
}

func (t *Txn) Rollback(ctx context.Context) error {
	if !t.active {
		return nil
	}
	_, err := t.c.IptablesRestore(t.v6, t.backup)
	return err
}

// ExecInTxn：执行命令，失败自动回滚
func (t *Txn) ExecInTxn(ctx context.Context, raw string, opts ...ExecOption) (Result, error) {
	if !t.active {
		return Result{}, fmt.Errorf("txn not active")
	}
	res := t.c.Exec(ctx, raw, opts...)
	if res.Err != nil {
		_ = t.Rollback(ctx)
		return res, res.Err
	}
	return res, nil
}
