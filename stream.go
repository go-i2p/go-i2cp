package go_i2cp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

// Stream provides I2CP-specific message serialization operations.
// It wraps bytes.Buffer and adds methods for reading/writing I2CP protocol data structures.
//
// The Stream type focuses on I2CP protocol serialization including:
//   - Binary integer encoding (big-endian uint16/32/64)
//   - Length-prefixed strings
//   - I2CP property mappings (key=value; format)
//
// For general binary operations outside I2CP, use encoding/binary directly.
type Stream struct {
	*bytes.Buffer
}

// NewStream creates a new Stream from a byte slice.
// The Stream wraps a bytes.Buffer initialized with the provided data.
func NewStream(buf []byte) *Stream {
	return &Stream{bytes.NewBuffer(buf)}
}

// ReadUint16 reads a big-endian uint16 from the stream.
// This is commonly used for I2CP session IDs and length prefixes.
func (s *Stream) ReadUint16() (uint16, error) {
	bts := make([]byte, 2)
	_, err := s.Read(bts)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(bts), nil
}

// ReadUint32 reads a big-endian uint32 from the stream.
// This is commonly used for I2CP message IDs, sizes, and tunnel IDs.
func (s *Stream) ReadUint32() (uint32, error) {
	bts := make([]byte, 4)
	_, err := s.Read(bts)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(bts), nil
}

// ReadUint64 reads a big-endian uint64 from the stream.
// This is commonly used for I2CP timestamps.
func (s *Stream) ReadUint64() (uint64, error) {
	bts := make([]byte, 8)
	_, err := s.Read(bts)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(bts), nil
}

// WriteUint16 writes a big-endian uint16 to the stream.
// This is commonly used for I2CP session IDs and length prefixes.
func (s *Stream) WriteUint16(i uint16) error {
	bts := make([]byte, 2)
	binary.BigEndian.PutUint16(bts, i)
	_, err := s.Write(bts)
	return err
}

// WriteUint32 writes a big-endian uint32 to the stream.
// This is commonly used for I2CP message IDs, sizes, and tunnel IDs.
func (s *Stream) WriteUint32(i uint32) error {
	bts := make([]byte, 4)
	binary.BigEndian.PutUint32(bts, i)
	_, err := s.Write(bts)
	return err
}

// WriteUint64 writes a big-endian uint64 to the stream.
// This is commonly used for I2CP timestamps.
func (s *Stream) WriteUint64(i uint64) error {
	bts := make([]byte, 8)
	binary.BigEndian.PutUint64(bts, i)
	_, err := s.Write(bts)
	return err
}

// WriteLenPrefixedString writes a string prefixed by its length as a single byte.
// Format: [length:1 byte][string data]
// This limits strings to 255 bytes, which is sufficient for I2CP property keys/values.
func (stream *Stream) WriteLenPrefixedString(s string) error {
	if len(s) > 255 {
		return fmt.Errorf("string too long: %d bytes (max 255)", len(s))
	}
	err := stream.WriteByte(uint8(len(s)))
	if err != nil {
		return err
	}
	_, err = stream.WriteString(s)
	return err
}

// WriteMapping writes an I2CP property mapping to the stream.
// Format: [size:uint16][key1_len:1][key1][=][value1_len:1][value1][;]...[keyN_len:1][keyN][=][valueN_len:1][valueN][;]
//
// The mapping is a collection of key=value pairs separated by semicolons.
// Keys are sorted alphabetically for deterministic serialization.
// Empty keys are skipped to avoid malformed output.
//
// This format is used throughout I2CP for session configuration properties.
func (stream *Stream) WriteMapping(m map[string]string) error {
	buf := NewStream(make([]byte, 0))

	// Sort keys for deterministic output
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "" { // Skip empty keys
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	// Write each key=value; pair
	for _, key := range keys {
		if err := buf.WriteLenPrefixedString(key); err != nil {
			return fmt.Errorf("failed to write key %q: %w", key, err)
		}
		if err := buf.WriteByte(byte('=')); err != nil {
			return err
		}
		if err := buf.WriteLenPrefixedString(m[key]); err != nil {
			return fmt.Errorf("failed to write value for key %q: %w", key, err)
		}
		if err := buf.WriteByte(byte(';')); err != nil {
			return err
		}
	}

	// Write size prefix and mapping data
	if err := stream.WriteUint16(uint16(buf.Len())); err != nil {
		return err
	}
	_, err := stream.Write(buf.Bytes())
	return err
}

// ReadMapping reads an I2CP property mapping from the stream.
// Format: [size:uint16][key1_len:1][key1][=][value1_len:1][value1][;]...[keyN_len:1][keyN][=][valueN_len:1][valueN][;]
//
// Returns a map of key-value pairs. If the mapping is empty (size=0), returns an empty map.
// Returns an error if the mapping data is malformed or incomplete.
func (stream *Stream) ReadMapping() (map[string]string, error) {
	// Read the length of the mapping data
	mappingLength, err := stream.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to read mapping length: %w", err)
	}

	if mappingLength == 0 {
		return make(map[string]string), nil
	}

	// Read the mapping data
	mappingData := make([]byte, mappingLength)
	n, err := stream.Read(mappingData)
	if err != nil {
		return nil, fmt.Errorf("failed to read mapping data: %w", err)
	}
	if n != int(mappingLength) {
		return nil, fmt.Errorf("incomplete mapping data: expected %d bytes, got %d", mappingLength, n)
	}

	// Parse the mapping data
	result := make(map[string]string)
	dataStream := NewStream(mappingData)

	for dataStream.Len() > 0 {
		// Read key length and key
		keyLen, err := dataStream.ReadByte()
		if err != nil {
			break // End of data
		}

		keyBytes := make([]byte, keyLen)
		n, err := dataStream.Read(keyBytes)
		if err != nil || n != int(keyLen) {
			return nil, fmt.Errorf("failed to read key data")
		}
		key := string(keyBytes)

		// Read '=' separator
		sep, err := dataStream.ReadByte()
		if err != nil || sep != '=' {
			return nil, fmt.Errorf("expected '=' separator, got %c", sep)
		}

		// Read value length and value
		valueLen, err := dataStream.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("failed to read value length")
		}

		valueBytes := make([]byte, valueLen)
		n, err = dataStream.Read(valueBytes)
		if err != nil || n != int(valueLen) {
			return nil, fmt.Errorf("failed to read value data")
		}
		value := string(valueBytes)

		// Read ';' separator
		sep, err = dataStream.ReadByte()
		if err != nil || sep != ';' {
			return nil, fmt.Errorf("expected ';' separator, got %c", sep)
		}

		result[key] = value
	}

	return result, nil
}

// Seek provides limited support for repositioning within the stream.
// Currently only supports Seek(0, 0) to reset to the beginning.
// This is used internally for I2CP message processing.
//
// For full io.Seeker support, use bytes.Reader instead.
func (s *Stream) Seek(offset int64, whence int) (int64, error) {
	// Only support reset to beginning (offset=0, whence=0)
	if whence == 0 && offset == 0 {
		// Create new buffer with same data to reset read position
		data := s.Bytes()
		s.Buffer = bytes.NewBuffer(data)
		return 0, nil
	}
	return 0, fmt.Errorf("seek operation only supports reset to beginning (0, 0)")
}
