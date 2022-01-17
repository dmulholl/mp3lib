// Package mp3lib is a simple library for parsing MP3 files.
package mp3lib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Library version.
const Version = "1.0.0"

// Flag controlling the display of debugging information.
var DebugMode = false

// MPEG version enum.
const (
	MPEGVersion2_5 = iota
	MPEGVersionReserved
	MPEGVersion2
	MPEGVersion1
)

// MPEG layer enum.
const (
	MPEGLayerReserved = iota
	MPEGLayerIII
	MPEGLayerII
	MPEGLayerI
)

// Channel mode enum.
const (
	Stereo = iota
	JointStereo
	DualChannel
	Mono
)

// Bit rates.
var v1l1_br = []int{0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448}
var v1l2_br = []int{0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384}
var v1l3_br = []int{0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320}
var v2l1_br = []int{0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256}
var v2l2_br = []int{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160}
var v2l3_br = []int{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160}

// Sampling rates.
var v1_sr = []int{44100, 48000, 32000}
var v2_sr = []int{22050, 24000, 16000}
var v25_sr = []int{11025, 12000, 8000}

// MP3Frame represents an individual frame parsed from an MP3 stream.
type MP3Frame struct {
	MPEGVersion   byte
	MPEGLayer     byte
	CrcProtection bool
	BitRate       int
	SamplingRate  int
	PaddingBit    bool
	PrivateBit    bool
	ChannelMode   byte
	ModeExtension byte
	CopyrightBit  bool
	OriginalBit   bool
	Emphasis      byte
	SampleCount   int
	FrameLength   int
	RawBytes      []byte
}

// ID3v1Tag represents an ID3v1 metadata tag.
type ID3v1Tag struct {
	RawBytes []byte
}

// ID3v2Tag represents an ID3v2 metadata tag.
type ID3v2Tag struct {
	RawBytes []byte
}

// NextFrame loads the next MP3 frame from the input stream. Skips over ID3
// tags and unrecognised/garbage data in the stream. Returns nil when the
// stream has been exhausted.
func NextFrame(stream io.Reader) *MP3Frame {
	for {
		obj := NextObject(stream)
		switch obj := obj.(type) {
		case *MP3Frame:
			return obj
		case *ID3v1Tag:
			debug("NextFrame: skipping ID3v1 tag")
		case *ID3v2Tag:
			debug("NextFrame: skipping ID3v2 tag")
		case nil:
			return nil
		}
	}
}

// NextID3v2Tag loads the next ID3v2 tag from the input stream, skipping all
// other data. Returns nil when the stream has been exhausted.
func NextID3v2Tag(stream io.Reader) *ID3v2Tag {
	for {
		obj := NextObject(stream)
		switch obj := obj.(type) {
		case *MP3Frame:
			debug("NextID3v2Tag: skipping MP3 frame")
		case *ID3v1Tag:
			debug("NextID3v2Tag: skipping ID3v1 tag")
		case *ID3v2Tag:
			return obj
		case nil:
			return nil
		}
	}
}

// NextObject loads the next recognised object from the input stream. Skips
// over unrecognised/garbage data. Returns *MP3Frame, *ID3v1Tag, *ID3v2Tag,
// or nil when the stream has been exhausted.
func NextObject(stream io.Reader) interface{} {

	// Each MP3 frame begins with a 4-byte header.
	buffer := make([]byte, 4)
	lastByte := buffer[3:]

	// Fill the header buffer.
	if ok := fillBuffer(stream, buffer); !ok {
		return nil
	}

	// Scan forward until we find an object or reach the end of the stream.
	for {

		// Check for an ID3v1 tag: 'TAG'.
		if buffer[0] == 84 && buffer[1] == 65 && buffer[2] == 71 {

			tag := &ID3v1Tag{}
			tag.RawBytes = make([]byte, 128)
			copy(tag.RawBytes, buffer)

			if ok := fillBuffer(stream, tag.RawBytes[4:]); !ok {
				return nil
			}

			return tag
		}

		// Check for an ID3v2 tag: 'ID3'.
		if buffer[0] == 73 && buffer[1] == 68 && buffer[2] == 51 {

			// Read the remainder of the 10 byte tag header.
			remainder := make([]byte, 6)
			if ok := fillBuffer(stream, remainder); !ok {
				return nil
			}

			// The last 4 bytes of the header indicate the length of the tag.
			// This length does not include the header itself.
			length :=
				(int(remainder[2]) << (7 * 3)) |
					(int(remainder[3]) << (7 * 2)) |
					(int(remainder[4]) << (7 * 1)) |
					(int(remainder[5]) << (7 * 0))

			tag := &ID3v2Tag{}
			tag.RawBytes = make([]byte, 10+length)
			copy(tag.RawBytes, buffer)
			copy(tag.RawBytes[4:], remainder)

			if ok := fillBuffer(stream, tag.RawBytes[10:]); !ok {
				return nil
			}

			return tag
		}

		// Check for a frame header, indicated by an 11-bit frame-sync
		// sequence.
		if buffer[0] == 0xFF && (buffer[1]&0xE0) == 0xE0 {

			frame := &MP3Frame{}

			if ok := parseHeader(buffer, frame); ok {
				debug("NextObject: found frame")

				frame.RawBytes = make([]byte, frame.FrameLength)
				copy(frame.RawBytes, buffer)

				if ok := fillBuffer(stream, frame.RawBytes[4:]); !ok {
					return nil
				}

				return frame
			}
		}

		// Nothing found. Shift the buffer forward by one byte and try again.
		debug("NextObject: sync error: skipping byte")
		buffer[0] = buffer[1]
		buffer[1] = buffer[2]
		buffer[2] = buffer[3]
		n, _ := stream.Read(lastByte)
		if n < 1 {
			return nil
		}
	}
}

// parseHeader attempts to parse a slice of 4 bytes as a valid MP3 header. The
// return value is a boolean indicating success. If the header is valid its
// values are written into the supplied MP3Frame struct.
func parseHeader(header []byte, frame *MP3Frame) bool {

	// MPEG version. (2 bits)
	frame.MPEGVersion = (header[1] & 0x18) >> 3
	if frame.MPEGVersion == MPEGVersionReserved {
		return false
	}

	// MPEG layer. (2 bits.)
	frame.MPEGLayer = (header[1] & 0x06) >> 1
	if frame.MPEGLayer == MPEGLayerReserved {
		return false
	}

	// CRC (cyclic redundency check) protection. (1 bit.)
	frame.CrcProtection = (header[1] & 0x01) == 0x00

	// Bit rate index. (4 bits.)
	bitRateIndex := (header[2] & 0xF0) >> 4
	if bitRateIndex == 0 || bitRateIndex == 15 {
		return false
	}

	// Bit rate.
	if frame.MPEGVersion == MPEGVersion1 {
		switch frame.MPEGLayer {
		case MPEGLayerI:
			frame.BitRate = v1l1_br[bitRateIndex] * 1000
		case MPEGLayerII:
			frame.BitRate = v1l2_br[bitRateIndex] * 1000
		case MPEGLayerIII:
			frame.BitRate = v1l3_br[bitRateIndex] * 1000
		}
	} else {
		switch frame.MPEGLayer {
		case MPEGLayerI:
			frame.BitRate = v2l1_br[bitRateIndex] * 1000
		case MPEGLayerII:
			frame.BitRate = v2l2_br[bitRateIndex] * 1000
		case MPEGLayerIII:
			frame.BitRate = v2l3_br[bitRateIndex] * 1000
		}
	}

	// Sampling rate index. (2 bits.)
	samplingRateIndex := (header[2] & 0x0C) >> 2
	if samplingRateIndex == 3 {
		return false
	}

	// Sampling rate.
	switch frame.MPEGVersion {
	case MPEGVersion1:
		frame.SamplingRate = v1_sr[samplingRateIndex]
	case MPEGVersion2:
		frame.SamplingRate = v2_sr[samplingRateIndex]
	case MPEGVersion2_5:
		frame.SamplingRate = v25_sr[samplingRateIndex]
	}

	// Padding bit. (1 bit.)
	frame.PaddingBit = (header[2] & 0x02) == 0x02

	// Private bit. (1 bit.)
	frame.PrivateBit = (header[2] & 0x01) == 0x01

	// Channel mode. (2 bits.)
	frame.ChannelMode = (header[3] & 0xC0) >> 6

	// Mode Extension. Valid only for Joint Stereo mode. (2 bits.)
	frame.ModeExtension = (header[3] & 0x30) >> 4
	if frame.ChannelMode != JointStereo && frame.ModeExtension != 0 {
		return false
	}

	// Copyright bit. (1 bit.)
	frame.CopyrightBit = (header[3] & 0x08) == 0x08

	// Original bit. (1 bit.)
	frame.OriginalBit = (header[3] & 0x04) == 0x04

	// Emphasis. (2 bits.)
	frame.Emphasis = (header[3] & 0x03)
	if frame.Emphasis == 2 {
		return false
	}

	// Number of samples in the frame. We need this to determine the frame size.
	if frame.MPEGVersion == MPEGVersion1 {
		switch frame.MPEGLayer {
		case MPEGLayerI:
			frame.SampleCount = 384
		case MPEGLayerII:
			frame.SampleCount = 1152
		case MPEGLayerIII:
			frame.SampleCount = 1152
		}
	} else {
		switch frame.MPEGLayer {
		case MPEGLayerI:
			frame.SampleCount = 384
		case MPEGLayerII:
			frame.SampleCount = 1152
		case MPEGLayerIII:
			frame.SampleCount = 576
		}
	}

	// If the padding bit is set we add an extra 'slot' to the frame length.
	// A layer I slot is 4 bytes long; layer II and III slots are 1 byte long.
	var padding int = 0

	if frame.PaddingBit {
		if frame.MPEGLayer == MPEGLayerI {
			padding = 4
		} else {
			padding = 1
		}
	}

	// Calculate the frame length in bytes. There's a lot of confusion online
	// about how to do this and definitive documentation is hard to find as
	// the official MP3 specification is not publicly available. The
	// basic formula seems to boil down to:
	//
	//     bytes_per_sample = (bit_rate / sampling_rate) / 8
	//     frame_length = sample_count * bytes_per_sample + padding
	//
	// In practice we need to rearrange this formula to avoid rounding errors.
	//
	// I can't find any definitive statement on whether this length is
	// supposed to include the 4-byte header and the optional 2-byte CRC.
	// Experimentation on mp3 files captured from the wild indicates that it
	// includes the header at least.
	frame.FrameLength =
		(frame.SampleCount/8)*frame.BitRate/frame.SamplingRate + padding

	return true
}

// getSideInfoSize returns the length in bytes of the side information section
// of the supplied MP3 frame.
func getSideInfoSize(frame *MP3Frame) (size int) {

	if frame.MPEGLayer == MPEGLayerIII {
		if frame.MPEGVersion == MPEGVersion1 {
			if frame.ChannelMode == Mono {
				size = 17
			} else {
				size = 32
			}
		} else {
			if frame.ChannelMode == Mono {
				size = 9
			} else {
				size = 17
			}
		}
	}

	return size
}

// IsXingHeader returns true if the supplied frame is an Xing VBR header.
func IsXingHeader(frame *MP3Frame) bool {

	// The Xing header begins directly after the side information block. We
	// also need to allow 4 bytes for the frame header.
	size := getSideInfoSize(frame)

	if len(frame.RawBytes) < 4+size+4 {
		return false
	}

	flag := frame.RawBytes[4+size : 4+size+4]
	if bytes.Equal(flag, []byte("Xing")) || bytes.Equal(flag, []byte("Info")) {
		return true
	}

	return false
}

// IsVbriHeader returns true if the supplied frame is a Fraunhofer VBRI header.
func IsVbriHeader(frame *MP3Frame) bool {

	// The VBRI header begins after a fixed 32-byte offset. We also need to
	// allow 4 bytes for the frame header.
	if len(frame.RawBytes) < 4+32+4 {
		return false
	}

	flag := frame.RawBytes[4+32 : 4+32+4]
	if bytes.Equal(flag, []byte("VBRI")) {
		return true
	}

	return false
}

// NewXingHeader creates a new Xing header frame for a VBR file.
func NewXingHeader(totalFrames, totalBytes uint32) *MP3Frame {

	// We need a valid MP3 frame to use as a template. The data here is
	// arbitrary, taken from an MP3 file captured from the wild.
	frame := &MP3Frame{}
	frame.RawBytes = make([]byte, 209)
	frame.RawBytes[0] = 0xFF
	frame.RawBytes[1] = 0xFB
	frame.RawBytes[2] = 0x52
	frame.RawBytes[3] = 0xC0
	parseHeader(frame.RawBytes[:4], frame)

	// Determine the Xing header offset.
	offset := 4 + getSideInfoSize(frame)

	// Write the Xing header ID.
	copy(frame.RawBytes[offset:offset+4], []byte("Xing"))

	// Write a flag indicating that the number-of-frames and number-of-bytes
	// fields are present.
	frame.RawBytes[offset+7] = 3

	// Write the number of frames as a 32-bit big endian integer.
	binary.BigEndian.PutUint32(frame.RawBytes[offset+8:offset+12], totalFrames)

	// Write the number of bytes as a 32-bit big endian integer.
	binary.BigEndian.PutUint32(frame.RawBytes[offset+12:offset+16], totalBytes)

	return frame
}

// Print debugging information to stderr.
func debug(message string) {
	if DebugMode {
		fmt.Fprintln(os.Stderr, "DEBUG:", message)
	}
}

// Attempt to read len(buffer) bytes from the input stream.  Returns a boolean
// indicating success.
func fillBuffer(stream io.Reader, buffer []byte) bool {
	n, _ := io.ReadFull(stream, buffer)
	if n < len(buffer) {
		return false
	}
	return true
}
