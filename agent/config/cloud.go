package config

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	migrate "github.com/rubenv/sql-migrate"
	"go.uber.org/zap"
)

var _ Manager = (*cloudConfigManager)(nil)

type cloudConfigManager struct {
	logger *zap.Logger
	config Cloud
	db     *sqlx.DB
}

func (cc *cloudConfigManager) migrateDB() error {
	migrations := &migrate.MemoryMigrationSource{
		Migrations: []*migrate.Migration{
			{
				Id: "cloud_config_1",
				Up: []string{
					`CREATE TABLE IF NOT EXISTS cloud_config (
						address TEXT NOT NULL,
						id TEXT	NOT NULL,
						key TEXT	NOT NULL,
						channel TEXT	NOT NULL,
						ts_created INTEGER NOT NULL
						)`,
				},
				Down: []string{
					"DROP TABLE cloud_config",
				},
			},
		},
	}

	_, err := migrate.Exec(cc.db.DB, "sqlite3", migrations, migrate.Up)

	return err
}

func (cc *cloudConfigManager) request(address string, token string, response interface{}, method string, body []byte) error {
	tlsConfig := &tls.Config{InsecureSkipVerify: false}
	if !cc.config.TLS.Verify {
		tlsConfig.InsecureSkipVerify = true
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := http.Client{
		Timeout:   time.Second * 10,
		Transport: transport,
	}
	URL := fmt.Sprintf("%s/api/v1/agents", address)

	req, err := http.NewRequest(method, URL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	cc.logger.Debug("cloud api request", zap.String("url", req.URL.String()), zap.ByteString("body", body))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	res, getErr := client.Do(req)
	if getErr != nil {
		return getErr
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			cc.logger.Error("failed to close response body", zap.Error(err))
		}
	}()

	if (res.StatusCode < 200) || (res.StatusCode > 299) {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("expected 2xx status code, no or invalid body: %d", res.StatusCode)
		}
		if body[0] == '{' {
			var jsonBody map[string]interface{}
			err := json.Unmarshal(body, &jsonBody)
			if err == nil {
				if errMsg, ok := jsonBody["error"]; ok {
					return fmt.Errorf("%d %s", res.StatusCode, errMsg)
				}
			}
		}
		return fmt.Errorf("%d %s", res.StatusCode, body)
	}

	err = json.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		return err
	}
	return nil
}

func (cc *cloudConfigManager) autoProvision(apiAddress string, token string) (MQTTConfig, error) {
	type AgentRes struct {
		ID        string `json:"id"`
		Key       string `json:"key"`
		ChannelID string `json:"channel_id"`
	}

	type AgentReq struct {
		Name      string            `json:"name"`
		AgentTags map[string]string `json:"agent_tags"`
	}

	aname := cc.config.Config.AgentName
	if aname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return MQTTConfig{}, err
		}
		aname = hostname
	}

	agentReq := AgentReq{Name: strings.Replace(aname, ".", "-", -1), AgentTags: cc.config.Tags}
	body, err := json.Marshal(agentReq)
	if err != nil {
		return MQTTConfig{}, err
	}

	cc.logger.Info("attempting auto provision", zap.String("address", apiAddress))

	var result AgentRes
	err = cc.request(apiAddress, token, &result, http.MethodPost, body)
	if err != nil {
		return MQTTConfig{}, err
	}

	// save to local config
	address := ""
	_, err = cc.db.Exec(`INSERT INTO cloud_config VALUES ($1, $2, $3, $4, datetime('now'))`, address, result.ID, result.Key, result.ChannelID)
	if err != nil {
		return MQTTConfig{}, err
	}

	return MQTTConfig{
		ID:        result.ID,
		Key:       result.Key,
		ChannelID: result.ChannelID,
	}, nil
}

func (cc *cloudConfigManager) GetConfig() (MQTTConfig, error) {
	cc.logger.Info("using local config db", zap.String("filename", cc.config.DB.File))
	db, err := sqlx.Connect("sqlite3", cc.config.DB.File)
	if err != nil {
		return MQTTConfig{}, err
	}

	cc.db = db
	// currently we require address to be specified, it cannot be auto provisioned.
	// this may change in the future
	mqtt := cc.config.MQTT

	if len(mqtt.ID) > 0 && len(mqtt.Key) > 0 && len(mqtt.ChannelID) > 0 {
		cc.logger.Info("using explicitly specified cloud configuration",
			zap.String("address", mqtt.Address),
			zap.String("id", mqtt.ID))
		return MQTTConfig{
			Address:   mqtt.Address,
			ID:        mqtt.ID,
			Key:       mqtt.Key,
			ChannelID: mqtt.ChannelID,
		}, nil
	}

	// if full config is not available, possibly attempt auto provision configuration
	if !cc.config.Config.AutoProvision {
		return MQTTConfig{}, errors.New("valid cloud MQTT config was not specified, and auto_provision was disabled")
	}

	err = cc.migrateDB()
	if err != nil {
		return MQTTConfig{}, err
	}

	// see if we have an existing auto provisioned configuration saved locally
	q := `SELECT id, key, channel FROM cloud_config ORDER BY ts_created DESC LIMIT 1`
	dba := MQTTConfig{}
	if err := cc.db.QueryRowx(q).Scan(&dba.ID, &dba.Key, &dba.ChannelID); err != nil {
		if err != sql.ErrNoRows {
			return MQTTConfig{}, err
		}
	} else {
		// successfully loaded previous auto provision
		dba.Address = mqtt.Address
		cc.logger.Info("using previous auto provisioned cloud configuration loaded from local storage",
			zap.String("address", mqtt.Address),
			zap.String("id", dba.ID))
		return dba, nil
	}

	// attempt a live auto provision
	apiConfig := cc.config.API
	if len(apiConfig.Token) == 0 {
		return MQTTConfig{}, errors.New("wanted to auto provision, but no API token was available")
	}

	result, err := cc.autoProvision(apiConfig.Address, apiConfig.Token)
	if err != nil {
		return MQTTConfig{}, err
	}
	result.Address = mqtt.Address
	cc.logger.Info("using auto provisioned cloud configuration",
		zap.String("address", mqtt.Address),
		zap.String("id", result.ID))

	result.Connect = true
	return result, nil
}

func (cc *cloudConfigManager) GetContext(ctx context.Context) context.Context {
	if cc.config.MQTT.ID != "" {
		ctx = context.WithValue(ctx, ContextKey("agent_id"), cc.config.MQTT.ID)
	} else {
		ctx = context.WithValue(ctx, ContextKey("agent_id"), "auto-provisioning-without-id")
	}
	return ctx
}
