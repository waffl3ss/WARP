package repl

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// dataTable is the dashboard's table widget.
//
// It replaces bubbles/table, which measures cell width with go-runewidth. go-runewidth is not
// ANSI-aware: a seven-character cell coloured with an SGR sequence measures nineteen columns,
// so every styled cell was truncated to a fragment of its own escape sequence. On screen that
// looked like an empty SIGNAL column, an empty SECURITY column, and rows that did not line up
// - with nothing in any log to explain it.
//
// Colour in this dashboard is not decoration. Signal strength, whether a network is in scope
// and whether management frames are protected are all read at a glance from colour, so the
// answer was to measure properly rather than to stop colouring. Everything here goes through
// lipgloss, which understands escape sequences.
//
// It also removes a whole class of crash. bubbles/table re-renders on SetColumns against rows
// that still have the old cell count, which panicked on any resize that brought a dropped
// column back.
type dataTable struct {
	cols []column
	rows []row

	cursor int
	// offset is the first visible row, so the cursor can be scrolled without redrawing
	// everything above it.
	offset int

	width  int
	height int
}

type column struct {
	Title string
	Width int
}

type row []string

// SetColumns replaces the column set.
//
// Rows are dropped rather than reinterpreted: a row built for the previous column set has
// cells in the wrong places, and rendering it would silently show the wrong values under the
// wrong headings. The caller repopulates immediately.
func (t *dataTable) SetColumns(cols []column) {
	t.cols = cols
	t.rows = nil
	t.clampCursor()
}

// Columns returns the current columns.
func (t *dataTable) Columns() []column { return t.cols }

// SetRows replaces the contents, keeping the cursor where it was where possible.
func (t *dataTable) SetRows(rows []row) {
	t.rows = rows
	t.clampCursor()
}

// Rows returns the current contents.
func (t *dataTable) Rows() []row { return t.rows }

// SelectedRow returns the row under the cursor, or nil.
func (t *dataTable) SelectedRow() row {
	if t.cursor < 0 || t.cursor >= len(t.rows) {
		return nil
	}
	return t.rows[t.cursor]
}

// Cursor returns the selected index.
func (t *dataTable) Cursor() int { return t.cursor }

// SetCursor moves the selection.
func (t *dataTable) SetCursor(i int) {
	t.cursor = i
	t.clampCursor()
}

// SetWidth sets the width available for the whole table.
func (t *dataTable) SetWidth(w int) { t.width = w }

// Width returns it.
func (t *dataTable) Width() int { return t.width }

// SetHeight sets the number of lines available, header included.
func (t *dataTable) SetHeight(h int) {
	t.height = h
	t.clampCursor()
}

// visibleRows is how many data rows fit under the header and its rule.
func (t *dataTable) visibleRows() int {
	n := t.height - 2
	if n < 1 {
		return 1
	}
	return n
}

func (t *dataTable) clampCursor() {
	if t.cursor >= len(t.rows) {
		t.cursor = len(t.rows) - 1
	}
	if t.cursor < 0 {
		t.cursor = 0
	}

	// Keep the cursor inside the visible window.
	vis := t.visibleRows()
	if t.cursor < t.offset {
		t.offset = t.cursor
	}
	if t.cursor >= t.offset+vis {
		t.offset = t.cursor - vis + 1
	}
	if max := len(t.rows) - vis; t.offset > max {
		t.offset = max
	}
	if t.offset < 0 {
		t.offset = 0
	}
}

// Update handles cursor movement.
func (t *dataTable) Update(msg tea.Msg) (*dataTable, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return t, nil
	}

	switch key.String() {
	case "up", "ctrl+p":
		t.cursor--
	case "down", "ctrl+n":
		t.cursor++
	case "pgup":
		t.cursor -= t.visibleRows()
	case "pgdown", " ":
		t.cursor += t.visibleRows()
	case "home", "g":
		t.cursor = 0
	case "end", "G":
		t.cursor = len(t.rows) - 1
	default:
		return t, nil
	}
	t.clampCursor()
	return t, nil
}

// cell fits one value to a column, measuring escape sequences as the zero width they occupy.
//
// lipgloss truncates and pads ANSI-aware, which is the whole reason this type exists.
func cell(value string, width int) string {
	if width <= 0 {
		return ""
	}
	return lipgloss.NewStyle().
		Width(width).
		MaxWidth(width).
		Inline(true).
		Render(value)
}

// View renders the table.
func (t *dataTable) View() string {
	var b strings.Builder

	// Header.
	head := make([]string, 0, len(t.cols))
	for _, c := range t.cols {
		if c.Width <= 0 {
			continue
		}
		// The same leading space the data cells get, or every heading sits one column left of
		// its own values and the whole table looks skewed.
		head = append(head, cell(" "+sTableHead.Render(c.Title), c.Width+cellPadding))
	}
	b.WriteString(strings.Join(head, ""))
	b.WriteByte('\n')

	// Rule under the header, exactly as wide as the columns are.
	ruleW := 0
	for _, c := range t.cols {
		if c.Width > 0 {
			ruleW += c.Width + cellPadding
		}
	}
	b.WriteString(sDim.Render(strings.Repeat("─", maxInt(ruleW, 1))))

	vis := t.visibleRows()
	for i := t.offset; i < len(t.rows) && i < t.offset+vis; i++ {
		b.WriteByte('\n')

		cells := make([]string, 0, len(t.cols))
		for j, c := range t.cols {
			if c.Width <= 0 {
				continue
			}
			v := ""
			if j < len(t.rows[i]) {
				v = t.rows[i][j]
			}
			cells = append(cells, cell(" "+v, c.Width+cellPadding))
		}
		line := strings.Join(cells, "")

		if i == t.cursor {
			// The selected row is repainted whole, so a cell's own colour does not fight the
			// highlight - on a busy screen the cursor has to be findable instantly.
			line = sTableSelected.Render(lipgloss.NewStyle().Inline(true).
				Render(stripANSI(line)))
			line = cell(line, ruleW)
		}
		b.WriteString(line)
	}

	return b.String()
}

// stripANSI removes escape sequences so a selected row can be recoloured as a unit.
//
// A CSI sequence is ESC, '[', then parameter and intermediate bytes, then one final byte in
// @-~. The '[' is itself inside that final-byte range, so it has to be consumed explicitly -
// treating it as the terminator leaves "38;5;48m" behind as visible text.
func stripANSI(s string) string {
	var out strings.Builder
	out.Grow(len(s))

	const (
		text = iota
		afterESC
		inCSI
	)
	state := text

	for _, r := range s {
		switch state {
		case text:
			if r == '\x1b' {
				state = afterESC
				continue
			}
			out.WriteRune(r)
		case afterESC:
			if r == '[' {
				state = inCSI
				continue
			}
			// A two-character escape; nothing further to skip.
			state = text
		case inCSI:
			if r >= '@' && r <= '~' {
				state = text
			}
		}
	}
	return out.String()
}
