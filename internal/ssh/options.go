package ssh

import (
	"strings"
)

func buildCommand(raw string, opts ...ExecOption) Command {
	cmd := Command{Raw: raw}
	for _, o := range opts {
		o(&cmd)
	}
	// Args -> Raw
	if cmd.Raw == "" && len(cmd.Args) > 0 {
		cmd.Raw = strings.Join(cmd.Args, " ")
	}
	return cmd
}
