package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/policy"
)

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
		Addr:    fmt.Sprintf("%s:%d", host, port),
		Handler: server.router,
	}

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
	if t := c.Request.Header.Get("Content-type"); t != "application/x-yaml" {
		c.IndentedJSON(http.StatusBadRequest, Response{"invalid Content-Type. Only 'application/x-yaml' is supported"})
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
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
