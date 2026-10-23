package eventbus

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"alinksec/pkg/logger"

	"github.com/nats-io/nats.go"
)

// EventMessage 统一流转于 NATS 生产事件总线中的威胁报文
type EventMessage struct {
	EventID     string    `json:"event_id"`
	SourceType  string    `json:"source_type"`
	AgentID     string    `json:"agent_id"`
	SourceIP    string    `json:"source_ip"`
	Hostname    string    `json:"hostname"`
	Level       string    `json:"level"`
	RuleID      string    `json:"rule_id"`
	ThreatType  string    `json:"threat_type"`
	Message     string    `json:"message"`
	RawPayload  string    `json:"raw_payload"`
	EventTime   time.Time `json:"event_time"`
	ChainedHash string    `json:"chained_hash"`
}

// Bus 生产级事件总线统一接口
type Bus interface {
	Publish(subject string, msg *EventMessage) error
	Subscribe(subject string, handler func(msg *EventMessage)) (func(), error)
	Close() error
}

// NatsBus 基于 NATS 消息中枢的生产事件总线
type NatsBus struct {
	nc     *nats.Conn
	mu     sync.RWMutex
	closed bool
}

// NewNatsBus 初始化 NATS 事件总线连接
func NewNatsBus(url string) (*NatsBus, error) {
	opts := []nats.Option{
		nats.Name("alinksec-eventbus"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			logger.Warn("NATS eventbus disconnected", "err", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info("NATS eventbus reconnected", "url", nc.ConnectedUrl())
		}),
	}

	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nats: %w", err)
	}

	logger.Info("NATS production event bus connected successfully", "url", url)
	return &NatsBus{nc: nc}, nil
}

func (b *NatsBus) Publish(subject string, msg *EventMessage) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.nc == nil {
		return fmt.Errorf("nats bus is closed or nil")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return b.nc.Publish(subject, data)
}

func (b *NatsBus) Subscribe(subject string, handler func(msg *EventMessage)) (func(), error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.nc == nil {
		return nil, fmt.Errorf("nats bus is closed or nil")
	}

	sub, err := b.nc.Subscribe(subject, func(m *nats.Msg) {
		var msg EventMessage
		if err := json.Unmarshal(m.Data, &msg); err == nil {
			handler(&msg)
		}
	})
	if err != nil {
		return nil, err
	}

	return func() {
		_ = sub.Unsubscribe()
	}, nil
}

func (b *NatsBus) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed && b.nc != nil {
		b.closed = true
		b.nc.Close()
		logger.Info("NATS event bus closed")
	}
	return nil
}

// MemoryBus 纯内存回退事件总线 (支持离线、脱机和单测)
type MemoryBus struct {
	mu          sync.RWMutex
	subscribers map[string][]func(msg *EventMessage)
}

// NewMemoryBus 创建纯内存无外部依赖事件总线
func NewMemoryBus() *MemoryBus {
	return &MemoryBus{
		subscribers: make(map[string][]func(msg *EventMessage)),
	}
}

func (m *MemoryBus) Publish(subject string, msg *EventMessage) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if handlers, ok := m.subscribers[subject]; ok {
		for _, h := range handlers {
			go h(msg)
		}
	}
	// 通配符主题广播
	if handlers, ok := m.subscribers["alinksec.events.*"]; ok {
		for _, h := range handlers {
			go h(msg)
		}
	}
	return nil
}

func (m *MemoryBus) Subscribe(subject string, handler func(msg *EventMessage)) (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.subscribers[subject] = append(m.subscribers[subject], handler)
	return func() {
		// unregister
	}, nil
}

func (m *MemoryBus) Close() error {
	return nil
}
