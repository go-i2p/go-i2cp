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
	keys := prepareMapKeys(m)

	if err := writeKeyValuePairs(buf, keys, m); err != nil {
		return err
	}

	return writeMappingData(stream, buf)
}

// prepareMapKeys extracts non-empty keys from the map and sorts them alphabetically.
// Returns a sorted slice of keys for deterministic serialization.
func prepareMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "" { // Skip empty keys
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// writeKeyValuePairs writes all key=value; pairs to the buffer stream.
// Each pair is formatted as: key_len|key|=|value_len|value|;
func writeKeyValuePairs(buf *Stream, keys []string, m map[string]string) error {
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
	return nil
}

// writeMappingData writes the size prefix followed by the mapping buffer data.
// Format: size_uint16 | mapping_data
func writeMappingData(stream, buf *Stream) error {
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
	mappingData, err := readMappingData(stream)
	if err != nil {
		return nil, err
	}

	if len(mappingData) == 0 {
		return make(map[string]string), nil
	}

	return parseMappingData(mappingData)
}

// readMappingData reads the length-prefixed mapping data from the stream.
// Returns the raw mapping bytes or an error if reading fails.
func readMappingData(stream *Stream) ([]byte, error) {
	mappingLength, err := stream.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to read mapping length: %w", err)
	}

	if mappingLength == 0 {
		return []byte{}, nil
	}

	mappingData := make([]byte, mappingLength)
	n, err := stream.Read(mappingData)
	if err != nil {
		return nil, fmt.Errorf("failed to read mapping data: %w", err)
	}
	if n != int(mappingLength) {
		return nil, fmt.Errorf("incomplete mapping data: expected %d bytes, got %d", mappingLength, n)
	}

	return mappingData, nil
}

// parseMappingData parses raw mapping bytes into a map of key-value pairs.
// The data format is: [key_len:1][key][=][value_len:1][value][;]...
func parseMappingData(mappingData []byte) (map[string]string, error) {
	result := make(map[string]string)
	dataStream := NewStream(mappingData)

	for dataStream.Len() > 0 {
		done, err := parseSingleMapping(dataStream, result)
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
	}

	return result, nil
}

// parseSingleMapping reads a single key-value pair from the stream and adds it to the result map.
// Returns (true, nil) when the stream is exhausted normally, (false, nil) on successful parse,
// or (false, error) on parse failure.
func parseSingleMapping(dataStream *Stream, result map[string]string) (bool, error) {
	key, err := readMappingKey(dataStream)
	if err != nil {
		if dataStream.Len() == 0 {
			return true, nil // Normal end of data
		}
		return false, err
	}

	value, err := readMappingValue(dataStream)
	if err != nil {
		return false, err
	}

	if err := readMappingSeparator(dataStream, ';'); err != nil {
		return false, err
	}

	result[key] = value
	return false, nil
}

// readMappingKey reads a length-prefixed key and its '=' separator from the stream.
// Returns the key string or an error if the format is invalid.
func readMappingKey(dataStream *Stream) (string, error) {
	keyLen, err := dataStream.ReadByte()
	if err != nil {
		return "", err
	}

	keyBytes := make([]byte, keyLen)
	n, err := dataStream.Read(keyBytes)
	if err != nil || n != int(keyLen) {
		return "", fmt.Errorf("failed to read key data")
	}

	if err := readMappingSeparator(dataStream, '='); err != nil {
		return "", err
	}

	return string(keyBytes), nil
}

// readMappingValue reads a length-prefixed value from the stream.
// Returns the value string or an error if the format is invalid.
func readMappingValue(dataStream *Stream) (string, error) {
	valueLen, err := dataStream.ReadByte()
	if err != nil {
		return "", fmt.Errorf("failed to read value length")
	}

	valueBytes := make([]byte, valueLen)
	n, err := dataStream.Read(valueBytes)
	if err != nil || n != int(valueLen) {
		return "", fmt.Errorf("failed to read value data")
	}

	return string(valueBytes), nil
}

// readMappingSeparator reads and validates a separator byte from the stream.
// Returns an error if the expected separator is not found.
func readMappingSeparator(dataStream *Stream, expected byte) error {
	sep, err := dataStream.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read separator")
	}
	if sep != expected {
		return fmt.Errorf("expected '%c' separator, got '%c'", expected, sep)
	}
	return nil
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
