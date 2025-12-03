package go_i2cp

import (
	"fmt"
	"time"
)

// EnableBatching enables message batching with the specified flush timer and size threshold.
// flushTimer: duration to wait before flushing batch (e.g., 10ms)
// sizeThreshold: size in bytes to trigger immediate flush (e.g., 16KB)
// This starts a background goroutine that periodically flushes the output queue.
func (c *Client) EnableBatching(flushTimer time.Duration, sizeThreshold int) {
	c.batchMu.Lock()
	defer c.batchMu.Unlock()

	if c.batchEnabled {
		Warning("Message batching already enabled")
		return
	}

	c.batchFlushTimer = flushTimer
	c.batchSizeThreshold = sizeThreshold
	c.batchEnabled = true

	// Start background flush ticker
	c.batchTicker = time.NewTicker(flushTimer)
	c.wg.Add(1)
	go c.batchFlushWorker()

	Info("Message batching enabled (timer=%v, threshold=%d bytes)", flushTimer, sizeThreshold)
}

// DisableBatching disables message batching and stops the flush timer.
// Any pending messages in the queue will be flushed before disabling.
func (c *Client) DisableBatching() error {
	c.batchMu.Lock()
	defer c.batchMu.Unlock()

	if !c.batchEnabled {
		return nil
	}

	// Stop ticker
	if c.batchTicker != nil {
		c.batchTicker.Stop()
		c.batchTicker = nil
	}

	c.batchEnabled = false

	// Flush any remaining messages
	if err := c.flushOutputQueue(); err != nil {
		return fmt.Errorf("failed to flush queue during disable: %w", err)
	}

	Info("Message batching disabled")
	return nil
}

// IsBatchingEnabled returns whether message batching is currently enabled.
func (c *Client) IsBatchingEnabled() bool {
	c.batchMu.Lock()
	defer c.batchMu.Unlock()
	return c.batchEnabled
}

// batchFlushWorker runs in a background goroutine and periodically flushes the output queue.
func (c *Client) batchFlushWorker() {
	defer c.wg.Done()

	// Get the ticker channel
	c.batchMu.Lock()
	if c.batchTicker == nil {
		c.batchMu.Unlock()
		return
	}
	tickerChan := c.batchTicker.C
	c.batchMu.Unlock()

	for {
		select {
		case <-c.shutdown:
			// Flush any remaining messages before shutdown
			_ = c.flushOutputQueue()
			return
		case <-tickerChan:
			// Periodic flush on timer
			if err := c.flushOutputQueue(); err != nil {
				Warning("Batch flush failed: %v", err)
			}
		}
	}
}

// getTotalQueueSize calculates the total size of all messages in the output queue.
// Caller must hold c.lock.
func (c *Client) getTotalQueueSize() int {
	total := 0
	for _, stream := range c.outputQueue {
		total += stream.Len()
	}
	return total
}

// flushOutputQueue sends all queued messages and clears the queue.
// This method acquires its own lock and is safe to call concurrently.
func (c *Client) flushOutputQueue() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if len(c.outputQueue) == 0 {
		return nil
	}

	queueSize := len(c.outputQueue)
	totalBytes := c.getTotalQueueSize()

	Debug("Flushing batch: %d messages, %d bytes", queueSize, totalBytes)

	// Send all queued messages
	for _, stream := range c.outputQueue {
		// Track bandwidth and messages
		if c.metrics != nil {
			c.metrics.AddBytesSent(uint64(stream.Len()))
			// Message type is embedded in the stream at offset 4
			if stream.Len() >= 5 {
				msgType := stream.Bytes()[4]
				c.metrics.IncrementMessageSent(msgType)
			}
		}

		ret, err := c.tcp.Send(stream)
		if ret < 0 {
			return fmt.Errorf("failed to send batched message: %w", err)
		}
		if ret == 0 {
			// Connection not ready, leave remaining messages in queue
			Warning("Connection not ready during batch flush")
			break
		}
	}

	// Clear the queue
	c.outputQueue = make([]*Stream, 0)

	return nil
}
