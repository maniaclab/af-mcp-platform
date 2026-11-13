// Command rigctl-mcp exposes a facility rig scheduler over MCP (eval fixture).
package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("rigctl", "0.1.0")

	s.AddTool(
		mcp.NewTool("list_rigs",
			mcp.WithDescription("List rigs"),
			mcp.WithString("owner", mcp.Description("Owner account")),
		),
		listRigs,
	)

	s.AddTool(
		mcp.NewTool("rig_reserve",
			mcp.WithDescription("Reserve a rig for a number of hours and return the reservation."),
			mcp.WithString("rig", mcp.Required()),
			mcp.WithNumber("hours"),
			mcp.WithString("password", mcp.Description("Scheduler password")),
		),
		reserveRig,
	)

	// Default (stateful) streamable HTTP server.
	httpServer := server.NewStreamableHTTPServer(s)
	if err := httpServer.Start(":8000"); err != nil {
		log.Fatal(err)
	}
}

func listRigs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	owner := req.GetString("owner", "")
	out, err := exec.CommandContext(ctx, "rigctl", "list", "--owner", owner).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("rigctl failed: %w", err)
	}
	return mcp.NewToolResultText(string(out)), nil
}

func reserveRig(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	rig, err := req.RequireString("rig")
	if err != nil {
		return mcp.NewToolResultText("error: " + err.Error()), nil
	}
	hours := req.GetInt("hours", 1)
	out, err := exec.CommandContext(ctx, "rigctl", "reserve", rig, fmt.Sprint(hours),
		"--password", req.GetString("password", "")).CombinedOutput()
	if err != nil {
		return mcp.NewToolResultText(string(out)), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}
