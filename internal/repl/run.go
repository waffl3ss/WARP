package repl

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/waffl3ss/warp/internal/rpc"
)

// Run attaches an interactive console to a running daemon.
//
// The console holds no engagement state. Closing it, losing the SSH session it runs in, or
// killing it outright changes nothing: the daemon owns the radios and every running job, and
// reconnecting picks up exactly where things stand.
func Run(ctx context.Context, socket string) error {
	client, err := rpc.Dial(socket)
	if err != nil {
		return err
	}
	defer client.Close()

	m := New(ctx, client, socket)
	m.appendLine(styleDim.Render("WARP console attached to " + socket + "."))
	m.appendLine(styleDim.Render(
		"Number keys switch tabs. Detaching stops nothing - the daemon owns the radios and jobs."))

	p := tea.NewProgram(m,
		tea.WithContext(ctx),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	if _, err := p.Run(); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("repl: %w", err)
	}
	return nil
}
