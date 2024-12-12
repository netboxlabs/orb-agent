package server

import (
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/netboxlabs/orb-discovery/network-discovery/config"
	"github.com/netboxlabs/orb-discovery/network-discovery/policy"
)

// Response represents the server response
type Response struct {
	Detail string `json:"detail"`
}

// Capabilities represents the response for server capabilities
type Capabilities struct {
	Capabilities []string `json:"capabilities"`
}

// Server represents the network-discovery server
type Server struct {
	router  *gin.Engine
	manager *policy.Manager
	stat    config.Status
	logger  *slog.Logger
	host    string
	port    int
}

func init() {
	gin.SetMode(gin.ReleaseMode)
}

// NewServer returns a new network-discovery server
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

	v1 := server.router.Group("/api/v1")
	{
		v1.GET("/status", server.getStatus)
		v1.GET("/capabilities", server.getCapabilities)
		v1.POST("/policies", server.createPolicy)
		v1.DELETE("/policies/:policy", server.deletePolicy)
	}

	return server
}

// Router returns the router
func (s *Server) Router() *gin.Engine {
	return s.router
}

// Start starts the network-discovery server
func (s *Server) Start() {
	go func() {
		serv := fmt.Sprintf("%s:%d", s.host, s.port)
		s.logger.Info("starting network-discovery server at: " + serv)
		if err := s.router.Run(serv); err != nil {
			s.logger.Error("shutting down the server", "error", err)
		}
	}()
}

func (s *Server) getStatus(c *gin.Context) {
	s.stat.UpTimeSeconds = int64(math.Round(time.Since(s.stat.StartTime).Seconds()))
	c.IndentedJSON(http.StatusOK, s.stat)
}

func (s *Server) getCapabilities(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, Capabilities{Capabilities: s.manager.GetCapabilities()})
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

	rPolicies := []string{}
	for name, policy := range policies {
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

		if err := s.manager.StartPolicy(name, policy); err != nil {
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
	policy := c.Param("policy")
	if !s.manager.HasPolicy(policy) {
		c.IndentedJSON(http.StatusNotFound, Response{"policy not found"})
		return
	}

	if err := s.manager.StopPolicy(policy); err != nil {
		c.IndentedJSON(http.StatusInternalServerError, Response{err.Error()})
	} else {
		c.IndentedJSON(http.StatusOK, Response{"policy '" + policy + "' was deleted"})
	}
}

// Stop stops the network-discovery server
func (s *Server) Stop() {
	if err := s.manager.Stop(); err != nil {
		s.logger.Error("stopping policy manager", "error", err)
	}
}
