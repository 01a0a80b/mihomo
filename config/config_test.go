package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseUDP(t *testing.T) {
	testCases := []struct {
		testName     string
		workerCount  int
		queueSize    int
		dropStrategy string
		want         *UDP
	}{
		{
			testName:     "Default",
			workerCount:  defaultUDPWorkerCount,
			queueSize:    defaultUDPQueueSize,
			dropStrategy: defaultUDPDropStrategy,
			want: &UDP{
				WorkerCount:  defaultUDPWorkerCount,
				QueueSize:    defaultUDPQueueSize,
				DropStrategy: defaultUDPDropStrategy,
			},
		},
		{
			testName:     "InvalidFallback",
			workerCount:  -1,
			queueSize:    0,
			dropStrategy: "invalid",
			want: &UDP{
				WorkerCount:  defaultUDPWorkerCount,
				QueueSize:    defaultUDPQueueSize,
				DropStrategy: defaultUDPDropStrategy,
			},
		},
		{
			testName:     "NegativeQueueSizeFallback",
			workerCount:  8,
			queueSize:    -5,
			dropStrategy: "drop",
			want: &UDP{
				WorkerCount:  8,
				QueueSize:    defaultUDPQueueSize,
				DropStrategy: "drop",
			},
		},
		{
			testName:     "ValidOverride",
			workerCount:  12,
			queueSize:    128,
			dropStrategy: "block",
			want: &UDP{
				WorkerCount:  12,
				QueueSize:    128,
				DropStrategy: "block",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			raw := &RawConfig{
				UDPWorkerCount:  testCase.workerCount,
				UDPQueueSize:    testCase.queueSize,
				UDPDropStrategy: testCase.dropStrategy,
			}
			got, err := parseUDP(raw)
			assert.NoError(t, err)
			assert.Equal(t, testCase.want, got)
		})
	}
}

func TestDefaultRawConfigUDP(t *testing.T) {
	raw := DefaultRawConfig()
	assert.Equal(t, defaultUDPWorkerCount, raw.UDPWorkerCount)
	assert.Equal(t, defaultUDPQueueSize, raw.UDPQueueSize)
	assert.Equal(t, defaultUDPDropStrategy, raw.UDPDropStrategy)
}
