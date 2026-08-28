package entity

import (
	"errors"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

var ErrEntryNotFound = errors.New("entity: no logged entry for label")

var ErrAppendUnavailable = errors.New("entity: log appender not available")

var ErrProofsUnavailable = errors.New("entity: proof builder not available")

const (
	maxLabelBytes  = 512
	maxRecordBytes = 8192
)

type Submission struct {
	Label    string
	Record   []byte
	Metadata []byte
}

func (s Submission) Validate() error {
	return validation.ValidateStruct(&s,
		validation.Field(&s.Label, validation.Required, validation.Length(1, maxLabelBytes)),
		validation.Field(&s.Record, validation.Required, validation.Length(1, maxRecordBytes)),
		validation.Field(&s.Metadata, validation.Length(0, maxRecordBytes)),
	)
}

type Entry struct {
	LabelHash   []byte
	Leaf        []byte
	Record      []byte
	Metadata    []byte
	VRFProof    []byte
	Index       *int64
	SubmittedAt time.Time
	IncludedAt  *time.Time
}

func (Entry) Validate() error { return nil }

type Receipt struct {
	Index     int64
	Leaf      []byte
	VRFProof  []byte
	Duplicate bool
}

func (Receipt) Validate() error { return nil }

type History struct {
	Label    string
	VRFProof []byte
	Entries  []Entry
}

func (History) Validate() error { return nil }
