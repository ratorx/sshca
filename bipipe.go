package main

import "io"

// Endpoint represents one end of a bi-directional pipe
type Endpoint struct {
	reader *io.PipeReader
	writer *io.PipeWriter
}

// Read implementation for io.ReadWriteCloser
func (p *Endpoint) Read(b []byte) (int, error) {
	return p.reader.Read(b)
}

// Write implementation for io.ReadWriteCloser
func (p *Endpoint) Write(b []byte) (int, error) {
	return p.writer.Write(b)
}

// Close implementation for io.ReadWriteCloser
func (p *Endpoint) Close() error {
	p.writer.Close()
	return p.reader.Close()
}

// NewBiPipe creates a new bi-directional Pipe, where the endpoints support both
// reading and writing.
func NewBiPipe() (Endpoint, Endpoint) {
	var left, right Endpoint
	left.reader, right.writer = io.Pipe()
	right.reader, left.writer = io.Pipe()
	return left, right
}