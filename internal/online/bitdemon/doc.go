// Package bitdemon implements the Demonware transport and crypto used by BOZ.
//
// The byte-buffer subset covers bool, signed 32-bit and unsigned 8/16/32/64-bit integers,
// NUL-terminated strings, blobs, and fixed raw bytes. The bit-buffer subset
// covers the authentication primitives: the type-check flag, five-bit
// type tags, bool, unsigned 8/16/32/64-bit integers, and fixed raw bytes.
// Arrays, ranged numbers, floating-point values, and general message envelopes
// are not implemented.
// The transport codec distinguishes normal frames from zero-length keepalives
// and the reserved 200-plus-uint32 buffer-availability control record.
package bitdemon
