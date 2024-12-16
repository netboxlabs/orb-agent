package networkdiscovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/netboxlabs/orb-agent/agent/backend"
)

func (d *networkDiscoveryBackend) getProcRunningStatus() (backend.RunningStatus, string, error) {
	if d.proc == nil {
		return backend.Unknown, "backend not started yet", nil
	}
	status := d.proc.Status()

	if status.Error != nil {
		errMsg := fmt.Sprintf("network-discovery process error: %v", status.Error)
		return backend.BackendError, errMsg, status.Error
	}

	if status.Complete {
		err := d.proc.Stop()
		return backend.Offline, "network-discovery process ended", err
	}

	if status.StopTs > 0 {
		return backend.Offline, "network-discovery process ended", nil
	}
	return backend.Running, "", nil
}

// note this needs to be stateless because it is called for multiple go routines
func (d *networkDiscoveryBackend) request(url string, payload interface{}, method string, body io.Reader, contentType string, timeout int32) error {
	client := http.Client{
		Timeout: time.Second * time.Duration(timeout),
	}

	status, _, err := d.getProcRunningStatus()
	if status != backend.Running {
		d.logger.Warn("skipping network discovery REST API request because process is not running or is unresponsive", zap.String("url", url), zap.String("method", method), zap.Error(err))
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

	if (res.StatusCode < 200) || (res.StatusCode > 299) {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return errors.New(fmt.Sprintf("non 2xx HTTP error code from network-discovery, no or invalid body: %d", res.StatusCode))
		}
		if len(body) == 0 {
			return errors.New(fmt.Sprintf("%d empty body", res.StatusCode))
		} else if body[0] == '{' {
			var jsonBody map[string]interface{}
			err := json.Unmarshal(body, &jsonBody)
			if err == nil {
				if errMsg, ok := jsonBody["error"]; ok {
					return errors.New(fmt.Sprintf("%d %s", res.StatusCode, errMsg))
				}
			}
		}
	}

	if res.Body != nil {
		err = json.NewDecoder(res.Body).Decode(&payload)
		if err != nil {
			return err
		}
	}
	return nil
}
