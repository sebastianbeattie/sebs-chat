package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/fasthttp/websocket"
)

type display struct {
	messages []string
	input    textinput.Model
	viewport viewport.Model
	width    int
	height   int
	ready    bool
}

type newMessage struct {
	sender  string
	message string
}

var (
	group     Group
	webSocket *websocket.Conn
	config    Config
)

func (m display) Init() tea.Cmd {
	return nil
}

func displayMessage(sender, message string) tea.Cmd {
	return func() tea.Msg {
		return newMessage{sender, message}
	}
}

func (m display) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if !m.ready {
			m.width = msg.Width
			m.height = msg.Height
			m.viewport = viewport.New(m.width, m.height-2)

			// Rebuild text input now that we know terminal width
			ti := textinput.New()
			ti.Placeholder = "Type a message..."
			ti.Focus()
			ti.CharLimit = 256
			ti.Width = m.width - 2

			m.input = ti
			m.ready = true
		}

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			text := m.input.Value()
			if strings.TrimSpace(text) != "" {
				err := sendMessage(webSocket, group, config, text)
				if err != nil {
					cmds = append(cmds, displayMessage("Error", err.Error()))
				} else {
					m.input.Reset()
					cmds = append(cmds, displayMessage("You", text))
				}
			}
		case tea.KeyEsc:
			return m, tea.Quit
		}

	case newMessage:
		formatted := fmt.Sprintf("%s: %s", msg.sender, msg.message)
		m.messages = append(m.messages, formatted)
		m.viewport.SetContent(strings.Join(m.messages, "\n"))
		m.viewport.GotoBottom()
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m display) View() string {
	return fmt.Sprintf("%s\n\n%s", m.viewport.View(), m.input.View())
}

func createUi(g Group, ws *websocket.Conn, c Config) error {
	group = g
	webSocket = ws
	config = c

	ti := textinput.New()
	ti.Placeholder = "Type a message..."
	ti.Focus()

	p := tea.NewProgram(display{
		input: ti,
	})

	_, err := p.Run()
	if err != nil {
		return fmt.Errorf("an error has occurred: %v", err)
	}
	return nil
}
