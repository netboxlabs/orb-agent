package backend

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"gopkg.in/yaml.v3"
)

// GetRunningStatus checks the status of the backend process
func GetRunningStatus(proc CmdInterface) (RunningStatus, string, error) {
	if proc == nil {
		return Unknown, "backend not started yet", nil
	}
	status := proc.Status()

	if status.Error != nil {
		errMsg := fmt.Sprintf("process error: %v", status.Error)
		return BackendError, errMsg, status.Error
	}

	if status.Complete {
		err := proc.Stop()
		return Offline, "backend process ended", err
	}

	if status.StopTs > 0 {
		return Offline, "backend process ended", nil
	}
	return Running, "", nil
}

// CommonRequest is a generic function to make HTTP requests to the backend
func CommonRequest(backendName string, proc CmdInterface, logger *slog.Logger, url string, payload any,
	method string, body io.Reader, contentType string, timeout int32, errorMsg string,
) error {
	client := http.Client{
		Timeout: time.Second * time.Duration(timeout),
	}

	status, _, err := GetRunningStatus(proc)
	if status != Running {
		logger.Warn("skipping REST API request because process is not running or is unresponsive",
			slog.String("backend", backendName), slog.String("url", url), slog.String("method", method), slog.Any("error", err))
		return err
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return fmt.Errorf("received error from payload %v", slog.Any("error", err))
	}

	req.Header.Add("Content-Type", contentType)
	res, getErr := client.Do(req)

	if getErr != nil {
		return fmt.Errorf("received error from payload %v", slog.Any("error", err))
	}

	defer func() {
		if err := res.Body.Close(); err != nil {
			logger.Error("failed to close response body", slog.Any("error", err))
		}
	}()

	if (res.StatusCode < 200) || (res.StatusCode > 299) {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("non 2xx HTTP error code from %s, no or invalid body: %d", backendName, res.StatusCode)
		}
		if len(body) == 0 {
			return fmt.Errorf("%d empty body", res.StatusCode)
		} else if body[0] == '{' {
			var jsonBody map[string]any
			if err := json.Unmarshal(body, &jsonBody); err == nil {
				if errMsg, ok := jsonBody[errorMsg]; ok {
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
