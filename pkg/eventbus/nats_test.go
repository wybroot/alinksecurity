package eventbus

import (
	"sync"
	"testing"
	"time"
)

func TestMemoryBusPubSub(t *testing.T) {
	bus := NewMemoryBus()
	defer bus.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	var receivedSubject string
	var receivedPayload string

	// 订阅特定主题
	_, err := bus.Subscribe("alinksec.events.waf", func(msg *EventMessage) {
		receivedSubject = "alinksec.events.waf"
		receivedPayload = msg.Message
		wg.Done()
	})
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}

	// 订阅通配符主题
	_, err = bus.Subscribe("alinksec.events.*", func(msg *EventMessage) {
		wg.Done()
	})
	if err != nil {
		t.Fatalf("failed to subscribe wildcard: %v", err)
	}

	// 发布消息
	err = bus.Publish("alinksec.events.waf", &EventMessage{
		EventID:    "evt-bus-01",
		SourceType: "AGENT_WAF",
		AgentID:    "waf-01",
		Message:    "XSS detected",
		EventTime:  time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to publish: %v", err)
	}

	wg.Wait()

	if receivedSubject != "alinksec.events.waf" || receivedPayload != "XSS detected" {
		t.Fatalf("unexpected message received: subject=%s, payload=%s", receivedSubject, receivedPayload)
	}
}
