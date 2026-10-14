package mcp

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/pkg/logger"
	markmcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/mcuadros/go-defaults"
)

const (
	EndpointPath       = "/mcp"
	maxRequestBodySize = 1 << 20
)

type Tool[T any, R any] interface {
	Name() string

	Description() string

	Execute(ctx context.Context, params T) (R, error)

	Validate(params T) error
}

// InputSchemaProvider lets a tool declare constraints that cannot be inferred
// from Go types alone, such as numeric ranges and documented defaults.
type InputSchemaProvider interface {
	InputSchemaOptions() []markmcp.ToolOption
}

// Annotations describe how a tool affects the system it talks to.
type Annotations struct {
	// ReadOnly tools never change anything.
	ReadOnly bool
	// Destructive tools may remove protection or data (meaningful only
	// when ReadOnly is false).
	Destructive bool
	// Idempotent tools have no further effect when repeated with the same
	// arguments.
	Idempotent bool
}

// AnnotationProvider lets a tool declare that it changes state. Tools that
// do not implement it are registered as read-only.
type AnnotationProvider interface {
	Annotations() Annotations
}

// ToolAnnotations returns the annotations of tool.
func ToolAnnotations(tool any) Annotations {
	if provider, ok := tool.(AnnotationProvider); ok {
		return provider.Annotations()
	}
	return Annotations{ReadOnly: true, Idempotent: true}
}

type Middleware func(http.Handler) http.Handler

type MCPServer struct {
	server    *server.MCPServer
	transport *server.StreamableHTTPServer
}

func NewMCPServer(name, version, instructions string) *MCPServer {
	s := server.NewMCPServer(
		name,
		version,
		server.WithInstructions(instructions),
		server.WithToolCapabilities(false),
		server.WithInputSchemaValidation(),
		server.WithStrictInputSchemaDefault(),
		server.WithOutputSchemaValidation(),
	)
	transport := server.NewStreamableHTTPServer(
		s,
		server.WithEndpointPath(EndpointPath),
		server.WithStateLess(true),
	)
	return &MCPServer{server: s, transport: transport}
}

// Server returns the underlying protocol server (in-process clients, tests).
func (s *MCPServer) Server() *server.MCPServer {
	return s.server
}

// ServeStdio speaks MCP over in and out until ctx ends or in is closed.
// Nothing else may write to out: logs go to stderr.
func (s *MCPServer) ServeStdio(ctx context.Context, in io.Reader, out io.Writer, errorLog io.Writer) error {
	stdio := server.NewStdioServer(s.server)
	stdio.SetErrorLogger(log.New(errorLog, "mcp: ", log.LstdFlags))
	return stdio.Listen(ctx, in, out)
}

// Handler exposes exactly one Streamable HTTP endpoint. Legacy /sse and
// /message routes are intentionally not mounted.
func (s *MCPServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(EndpointPath, http.MaxBytesHandler(s.transport, maxRequestBodySize))
	return mux
}

func (s *MCPServer) Start(addr string, middleware ...Middleware) error {
	return s.listen(addr, "", "", middleware...)
}

// StartTLS serves the same handler over HTTPS.
func (s *MCPServer) StartTLS(addr, certFile, keyFile string, middleware ...Middleware) error {
	if strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "" {
		return fmt.Errorf("tls cert and key are required")
	}
	return s.listen(addr, certFile, keyFile, middleware...)
}

func (s *MCPServer) listen(addr, certFile, keyFile string, middleware ...Middleware) error {
	var handler http.Handler = s.Handler()
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if certFile != "" {
		return srv.ListenAndServeTLS(certFile, keyFile)
	}
	return srv.ListenAndServe()
}

func handleToolCall[T any, R any](ctx context.Context, request markmcp.CallToolRequest, tool Tool[T, R]) (result *markmcp.CallToolResult, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logger.With("tool", tool.Name()).Error("tool execution panicked")
			result = markmcp.NewToolResultError("tool execution failed")
			err = nil
		}
	}()

	var params T
	defaults.SetDefaults(&params)
	if err := request.BindArguments(&params); err != nil {
		return markmcp.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if err := tool.Validate(params); err != nil {
		return markmcp.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	execResult, err := tool.Execute(ctx, params)
	if err != nil {
		logger.With("tool", tool.Name()).With("error", err).Error("tool execution failed")
		return markmcp.NewToolResultError(err.Error()), nil
	}

	result, err = markmcp.NewToolResultJSON(execResult)
	if err != nil {
		logger.With("tool", tool.Name()).With("error", err).Error("tool result serialization failed")
		return markmcp.NewToolResultError("tool result serialization failed"), nil
	}
	return result, nil
}

// Registrar is a tool with its generic types bound, ready to register.
type Registrar interface {
	Name() string
	Annotations() Annotations
	Register(s *MCPServer) error
}

// Wrap binds the generic types of tool.
func Wrap[T any, R any](tool Tool[T, R]) Registrar {
	return &wrapped[T, R]{tool: tool}
}

type wrapped[T any, R any] struct {
	tool Tool[T, R]
}

func (w *wrapped[T, R]) Name() string { return w.tool.Name() }

func (w *wrapped[T, R]) Annotations() Annotations { return ToolAnnotations(w.tool) }

func (w *wrapped[T, R]) Register(s *MCPServer) error {
	logger.Info("Registering tool", logger.String("name", w.tool.Name()))
	return RegisterTool(s, w.tool)
}

func RegisterTool[T any, R any](s *MCPServer, tool Tool[T, R]) error {
	options := []markmcp.ToolOption{
		markmcp.WithDescription(tool.Description()),
	}
	if provider, ok := any(tool).(InputSchemaProvider); ok {
		options = append(options, provider.InputSchemaOptions()...)
	} else {
		options = append(options, markmcp.WithInputSchema[T]())
	}
	annotations := ToolAnnotations(tool)
	options = append(options,
		markmcp.WithOutputSchema[R](),
		markmcp.WithReadOnlyHintAnnotation(annotations.ReadOnly),
		markmcp.WithDestructiveHintAnnotation(!annotations.ReadOnly && annotations.Destructive),
		markmcp.WithIdempotentHintAnnotation(annotations.Idempotent),
		markmcp.WithOpenWorldHintAnnotation(true),
	)
	t := markmcp.NewTool(tool.Name(), options...)

	s.server.AddTool(t, func(ctx context.Context, request markmcp.CallToolRequest) (*markmcp.CallToolResult, error) {
		return handleToolCall(ctx, request, tool)
	})
	return nil
}
