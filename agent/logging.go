package agent

import (
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"go.uber.org/zap"
)

type agentLoggerDebug struct {
	a *orbAgent
}
type agentLoggerWarn struct {
	a *orbAgent
}
type agentLoggerCritical struct {
	a *orbAgent
}
type agentLoggerError struct {
	a *orbAgent
}

var (
	_ mqtt.Logger = (*agentLoggerDebug)(nil)
	_ mqtt.Logger = (*agentLoggerWarn)(nil)
	_ mqtt.Logger = (*agentLoggerCritical)(nil)
	_ mqtt.Logger = (*agentLoggerError)(nil)
)

func (a *agentLoggerWarn) Println(v ...interface{}) {
	a.a.logger.Warn("WARN mqtt log", zap.Any("payload", v))
}

func (a *agentLoggerWarn) Printf(_ string, v ...interface{}) {
	a.a.logger.Warn("WARN mqtt log", zap.Any("payload", v))
}

func (a *agentLoggerDebug) Println(v ...interface{}) {
	a.a.logger.Debug("DEBUG mqtt log", zap.Any("payload", v))
}

func (a *agentLoggerDebug) Printf(_ string, v ...interface{}) {
	a.a.logger.Debug("DEBUG mqtt log", zap.Any("payload", v))
}

func (a *agentLoggerCritical) Println(v ...interface{}) {
	a.a.logger.Error("CRITICAL mqtt log", zap.Any("payload", v))
}

func (a *agentLoggerCritical) Printf(_ string, v ...interface{}) {
	a.a.logger.Error("CRITICAL mqtt log", zap.Any("payload", v))
}

func (a *agentLoggerError) Println(v ...interface{}) {
	a.a.logger.Error("ERROR mqtt log", zap.Any("payload", v))
}

func (a *agentLoggerError) Printf(_ string, v ...interface{}) {
	a.a.logger.Error("ERROR mqtt log", zap.Any("payload", v))
}
