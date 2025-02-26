package otel

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
)

func (d *openTelemetryBackend) getProcRunningStatus() (backend.RunningStatus, string, error) {
	if d.proc == nil {
		return backend.Unknown, "backend not started yet", nil
	}
	status := d.proc.Status()

	if status.Error != nil {
		errMsg := fmt.Sprintf("opentelemetry infinity process error: %v", status.Error)
		return backend.BackendError, errMsg, status.Error
	}

	if status.Complete {
		err := d.proc.Stop()
		return backend.Offline, "opentelemetry infinity process ended", err
	}

	if status.StopTs > 0 {
		return backend.Offline, "opentelemetry infinity process ended", nil
	}
	return backend.Running, "", nil
}

// note this needs to be stateless because it is called for multiple go routines
func (d *openTelemetryBackend) request(url string, payload interface{}, method string, body io.Reader, contentType string, timeout int32) error {
	client := http.Client{
		Timeout: time.Second * time.Duration(timeout),
	}

	status, _, err := d.getProcRunningStatus()
	if status != backend.Running {
		d.logger.Warn("skipping opentelemetry infinity REST API request because process is not running or is unresponsive", zap.String("url", url), zap.String("method", method), zap.Error(err))
		return err
	}

	URL := fmt.Sprintf("%s://%s:%s/api/v1/%s", d.apiProtocol, d.apiHost, d.apiPort, url)

	req, err := http.NewRequest(method, URL, body)
	if err != nil {
		d.logger.Error("received error from payload", zap.Error(err))
		return err
	}

	req.Header.Add("Content-Type", contentType)
	res, getErr := client.Do(req)

	if getErr != nil {
		d.logger.Error("received error from payload", zap.Error(getErr))
		return getErr
	}

	defer func() {
		if err := res.Body.Close(); err != nil {
			d.logger.Error("failed to close response body", zap.Error(err))
		}
	}()

	if (res.StatusCode < 200) || (res.StatusCode > 299) {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("non 2xx HTTP error code from opentelemetry infinity, no or invalid body: %d", res.StatusCode)
		}
		if len(body) == 0 {
			return fmt.Errorf("%d empty body", res.StatusCode)
		} else if body[0] == '{' {
			var jsonBody map[string]interface{}
			if err := json.Unmarshal(body, &jsonBody); err == nil {
				if errMsg, ok := jsonBody["message"]; ok {
					return fmt.Errorf("%d %s", res.StatusCode, errMsg)
				}
			} else {
				return fmt.Errorf("%d %s", res.StatusCode, body)
			}
		} else {
			return fmt.Errorf("%d %s", res.StatusCode, body)
		}
	}

	// Read and decode response body
	if res.Body != nil {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		if err = json.Unmarshal(body, &payload); err == nil {
			return nil
		}
		var yamlErr error
		if yamlErr = yaml.Unmarshal(body, &payload); yamlErr == nil {
			return nil
		}
		return fmt.Errorf("failed to decode response as JSON: %w and YAML: %w", err, yamlErr)
	}
	return nil
}
