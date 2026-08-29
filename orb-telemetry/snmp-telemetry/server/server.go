package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/policy"
)

// maxPolicyBodyBytes bounds every request body the server reads.
//
// The documented sample policy weighs 602 bytes and the richest sample in the
// repo docs, with every optional key set, weighs under 4 KiB. A target may be a
// CIDR prefix, so the 65536-address expansion cap costs one 30-byte line rather
// than an enumerated list, and device count does not drive body size. The bound
// still holds roughly 2900 targets that each spell out a full SNMPv3 block, or
// 32000 bare hosts, which is far past what one agent should poll.
const maxPolicyBodyBytes = 1 << 20

// Connection deadlines. maxPolicyBodyBytes bounds how many bytes a request may
// carry, not how long they may take, so without these a client holds a
// connection, and the goroutine behind it, indefinitely by trickling headers or
// a sub-limit body.
const (
	// A request line and a handful of headers, from a client on the same host
	// or the same network. Ten seconds is far past what that costs and is the
	// tighter of the two read bounds, so a stalled header is dropped without
	// waiting out the body window.
	readHeaderTimeout = 10 * time.Second
	// Headers plus the whole body. A body is capped at maxPolicyBodyBytes, so
	// thirty seconds asks a client sending the largest allowed policy to
	// sustain about 35 KiB/s. The agent posts a policy with a ten second client
	// timeout, so it gives up long before this does.
	readTimeout = 30 * time.Second
	// The write deadline starts when the request headers are read and covers
	// the body read, the handler and the response write, so it has to outlast
	// the slowest handler or a working request comes back truncated. The
	// slowest is DELETE /policies/:policy, which blocks on the runner's
	// scheduler shutdown: gocron bounds that by its stop timeout plus two
	// seconds, once for StopJobs and again for Shutdown, which is 24 seconds at
	// gocron's ten second default. POST /policies is nowhere near it, taking
	// under a second to schedule a policy at the full 65536-address budget.
	// Sixty seconds keeps that ceiling clear of the deadline even when the read
	// window is spent first.
	writeTimeout = 60 * time.Second
	// Keep-alive. Left unset, Go reuses ReadTimeout for idle connections, which
	// ties keep-alive to a bound that exists for a different reason. The agent
	// polls status every five seconds and its client pools connections, so a
	// minute keeps one warm across polls.
	idleTimeout = 60 * time.Second
)

// contentTypeYAML is the only media type the policy endpoint accepts.
const contentTypeYAML = "application/x-yaml"

// Response represents the server response
type Response struct {
	Detail string `json:"detail"`
}

// Capabilities represents the response for server capabilities
type Capabilities struct {
	Capabilities []string `json:"capabilities"`
}

// StatusResponse represents the status response including policies
type StatusResponse struct {
	config.Status
	Policies []policy.Status `json:"policies"`
}

// Server represents the snmp-telemetry server
type Server struct {
	router     *gin.Engine
	manager    *policy.Manager
	stat       config.Status
	logger     *slog.Logger
	host       string
	port       int
	httpServer *http.Server
}

func init() {
	gin.SetMode(gin.ReleaseMode)
}

// NewServer returns a new snmp-telemetry server
func NewServer(host string, port int, logger *slog.Logger, manager *policy.Manager, version string) *Server {
	server := &Server{
		router:  gin.New(),
		manager: manager,
		stat: config.Status{
			Version:   version,
			StartTime: time.Now(),
		},
		logger: logger,
		host:   host,
		port:   port,
	}
	server.httpServer = &http.Server{
		Addr:              fmt.Sprintf("%s:%d", host, port),
		Handler:           server.router,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	// Bound the body before routing, so a handler added later cannot read an
	// unbounded one. The reader is lazy: a handler that never reads pays nothing.
	server.router.Use(limitBodySize)

	v1 := server.router.Group("/api/v1")
	{
		v1.GET("/status", server.getStatus)
		v1.GET("/capabilities", server.getCapabilities)
		v1.GET("/policies", server.getPolicies)
		v1.POST("/policies", server.createPolicy)
		v1.DELETE("/policies/:policy", server.deletePolicy)
	}

	return server
}

func limitBodySize(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxPolicyBodyBytes)
	c.Next()
}

// Router returns the router
func (s *Server) Router() *gin.Engine {
	return s.router
}

// Start starts the snmp-telemetry server
func (s *Server) Start() <-chan error {
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("starting snmp-telemetry server", "address", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				close(errCh)
				return
			}
			errCh <- err
		}
		close(errCh)
	}()
	return errCh
}

func (s *Server) getStatus(c *gin.Context) {
	// The uptime is computed on a request-local copy. s.stat is written once at
	// construction and shared by every handler goroutine, so writing the field
	// back into it races two concurrent status requests against each other.
	stat := s.stat
	stat.UpTimeSeconds = int64(math.Round(time.Since(stat.StartTime).Seconds()))

	response := StatusResponse{
		Status:   stat,
		Policies: s.manager.GetPolicyStatuses(),
	}

	c.IndentedJSON(http.StatusOK, response)
}

func (s *Server) getCapabilities(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, Capabilities{Capabilities: s.manager.GetCapabilities()})
}

func (s *Server) getPolicies(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, s.manager.GetPolicyStatuses())
}

func (s *Server) createPolicy(c *gin.Context) {
	// Compare only the media type, so a charset parameter the client or a proxy
	// appended does not turn a valid submission away. ParseMediaType already
	// lower-cases the media type, so the comparison is case-insensitive as HTTP
	// requires. An absent or malformed header fails here and stays rejected: the
	// agent's client always sets the header, and the body is never sniffed.
	mediaType, _, err := mime.ParseMediaType(c.Request.Header.Get("Content-Type"))
	if err != nil || mediaType != contentTypeYAML {
		c.IndentedJSON(http.StatusBadRequest, Response{"invalid Content-Type. Only '" + contentTypeYAML + "' is supported"})
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.IndentedJSON(http.StatusRequestEntityTooLarge,
				Response{fmt.Sprintf("policy body exceeds the limit of %d bytes", maxPolicyBodyBytes)})
			return
		}
		c.IndentedJSON(http.StatusBadRequest, Response{err.Error()})
		return
	}

	policies, err := s.manager.ParsePolicies(body)
	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, Response{err.Error()})
		return
	}

	s.logger.Info("Received policies", "policyCount", len(policies))

	rPolicies := []string{}
	for name, pol := range policies {
		if s.manager.HasPolicy(name) {
			for _, p := range rPolicies {
				if err = s.manager.StopPolicy(p); err != nil {
					c.IndentedJSON(http.StatusInternalServerError, Response{err.Error()})
					return
				}
			}
			c.IndentedJSON(http.StatusConflict, Response{"policy '" + name + "' already exists"})
			return
		}

		if err := s.manager.StartPolicy(name, pol); err != nil {
			for _, p := range rPolicies {
				if sErr := s.manager.StopPolicy(p); sErr != nil {
					err = fmt.Errorf("%v: %v", err, sErr)
				}
			}
			c.IndentedJSON(http.StatusBadRequest, Response{err.Error()})
			return
		}
		rPolicies = append(rPolicies, name)
	}

	c.IndentedJSON(http.StatusCreated, Response{fmt.Sprintf("policies [%s] were started", strings.Join(rPolicies, ","))})
}

func (s *Server) deletePolicy(c *gin.Context) {
	pol := c.Param("policy")
	if !s.manager.HasPolicy(pol) {
		c.IndentedJSON(http.StatusNotFound, Response{"policy not found"})
		return
	}

	if err := s.manager.StopPolicy(pol); err != nil {
		c.IndentedJSON(http.StatusInternalServerError, Response{err.Error()})
	} else {
		c.IndentedJSON(http.StatusOK, Response{"policy '" + pol + "' was deleted"})
	}
}

// Stop stops the snmp-telemetry server
func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.logger.Error("shutting down HTTP server", "error", err)
	}

	if err := s.manager.Stop(); err != nil {
		s.logger.Error("stopping policy manager", "error", err)
	}
}
