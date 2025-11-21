package ssh

import (
	"bytes"
	"text/template"
)

type TemplateCommand struct {
	Tpl  string
	Data any
}

func (tc TemplateCommand) Render() (string, error) {
	t, err := template.New("cmd").Parse(tc.Tpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, tc.Data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
