package server

import (
	"time"

	"github.com/0xrawsec/whids/api"
)

// CommandAPI structure used by Admin API clients to POST commands
type CommandAPI struct {
	CommandLine string        `json:"command-line"`
	FetchFiles  []string      `json:"fetch-files"`
	DropFiles   []string      `json:"drop-files"`
	Timeout     time.Duration `json:"timeout"`
}

// ToCommand converts a CommandAPI to an EndpointCommand
func (c *CommandAPI) ToCommand() (*api.EndpointCommand, error) {
	cmd := api.NewEndpointCommand()
	// adding command line
	if err := cmd.SetCommandLine(c.CommandLine); err != nil {
		return cmd, err
	}

	// adding files to fetch
	for _, ff := range c.FetchFiles {
		cmd.AddFetchFile(ff)
	}

	// adding files to drop on the endpoint
	for _, df := range c.DropFiles {
		cmd.AddDropFileFromPath(df)
	}

	// clamp the requested timeout into a sane range so the agent always runs
	// the command with a finite timeout. A zero/negative value would
	// otherwise select the agent's no-timeout path (unbounded run), and an
	// excessive value could hang the single-threaded command runner.
	switch {
	case c.Timeout <= 0:
		cmd.Timeout = CommandTimeout // fall back to the default
	case c.Timeout < MinCommandTimeout:
		cmd.Timeout = MinCommandTimeout
	case c.Timeout > MaxCommandTimeout:
		cmd.Timeout = MaxCommandTimeout
	default:
		cmd.Timeout = c.Timeout
	}

	return cmd, nil
}
