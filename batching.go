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
	// Silently return if not initialized
	if err := c.ensureInitialized(); err != nil {
		return
	}

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
	// Return nil if not initialized (batching can't be enabled anyway)
	if err := c.ensureInitialized(); err != nil {
		return nil
	}

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
	// Return false if not initialized
	if err := c.ensureInitialized(); err != nil {
		return false
	}

	c.batchMu.Lock()
	defer c.batchMu.Unlock()
	return c.batchEnabled
}

// batchFlushWorker runs in a background goroutine and periodically flushes the output queue.
func (c *Client) batchFlushWorker() {
	defer c.wg.Done()

	tickerChan := c.getBatchTickerChannel()
	if tickerChan == nil {
		return
	}

	c.runFlushLoop(tickerChan)
}

// getBatchTickerChannel safely retrieves the batch ticker channel.
func (c *Client) getBatchTickerChannel() <-chan time.Time {
	c.batchMu.Lock()
	defer c.batchMu.Unlock()

	if c.batchTicker == nil {
		return nil
	}
	return c.batchTicker.C
}

// runFlushLoop runs the main flush worker loop until shutdown.
func (c *Client) runFlushLoop(tickerChan <-chan time.Time) {
	for {
		select {
		case <-c.shutdown:
			_ = c.flushOutputQueue()
			return
		case <-tickerChan:
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

	c.logFlushStart()

	if err := c.sendQueuedMessages(); err != nil {
		return err
	}

	c.clearQueue()
	return nil
}

// logFlushStart logs the batch flush operation details.
func (c *Client) logFlushStart() {
	queueSize := len(c.outputQueue)
	totalBytes := c.getTotalQueueSize()
	Debug("Flushing batch: %d messages, %d bytes", queueSize, totalBytes)
}

// sendQueuedMessages sends all messages currently in the output queue.
func (c *Client) sendQueuedMessages() error {
	for _, stream := range c.outputQueue {
		c.trackMessageMetrics(stream)

		ret, err := c.tcp.Send(stream)
		if ret < 0 {
			return fmt.Errorf("failed to send batched message: %w", err)
		}
		if ret == 0 {
			Warning("Connection not ready during batch flush")
			break
		}
	}
	return nil
}

// trackMessageMetrics updates bandwidth and message metrics for a queued message.
func (c *Client) trackMessageMetrics(stream *Stream) {
	if c.metrics != nil {
		c.metrics.AddBytesSent(uint64(stream.Len()))
		if stream.Len() >= 5 {
			msgType := stream.Bytes()[4]
			c.metrics.IncrementMessageSent(msgType)
		}
	}
}

// clearQueue resets the output queue to empty.
func (c *Client) clearQueue() {
	c.outputQueue = make([]*Stream, 0)
}
