// Copyright 2017 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package procfs

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type SCTP struct {
	CurrEstab               int64
	ActiveEstabs            int64
	PassiveEstabs           int64
	Aborteds                int64
	Shutdowns               int64
	OutOfBlues              int64
	ChecksumErrors          int64
	OutCtrlChunks           int64
	OutOrderChunks          int64
	OutUnorderChunks        int64
	InCtrlChunks            int64
	InOrderChunks           int64
	InUnorderChunks         int64
	FragUsrMsgs             int64
	ReasmUsrMsgs            int64
	OutSCTPPacks            int64
	InSCTPPacks             int64
	T1InitExpireds          int64
	T1CookieExpireds        int64
	T2ShutdownExpireds      int64
	T3RtxExpireds           int64
	T4RtoExpireds           int64
	T5ShutdownGuardExpireds int64
	DelaySackExpireds       int64
	AutocloseExpireds       int64
	T3Retransmits           int64
	PmtudRetransmits        int64
	FastRetransmits         int64
	InPktSoftirq            int64
	InPktBacklog            int64
	InPktDiscards           int64
	InDataChunkDiscards     int64
}

// NewBuddyInfo reads the buddyinfo statistics.
func NewSCTP() (BuddyInfo, error) {
	fs, err := NewFS(DefaultMountPoint)
	if err != nil {
		return nil, err
	}

	return fs.NewSCTP()
}

// NewBuddyInfo reads the buddyinfo statistics from the specified `proc` filesystem.
func (fs FS) NewSCTP() (SCTP, error) {
	file, err := os.Open(fs.Path("net/sctp/snmp"))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseSCTP(file)
}

func parseSCTP(r io.Reader) (SCTP, error) {
	var (
		sctp    = SCTP{}
		scanner = bufio.NewScanner(r)
	)

	for scanner.Scan() {
		var err error
		line := scanner.Text()
		parts := strings.Fields(string(line))

		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid number of fields when parsing SCTP")
		}

		name := parts[0]
		value, err := strconv.ParseInt(v, 64)
		if err != nil {
			return nil, err
		}

		switch name {
		case "SctpInCtrlChunks":
			sctp.InCtrlChunks = value
		case "SctpInOrderChunks":
			sctp.InOrderChunks = value
		case "SctpInUnorderChunks":
			sctp.InUnorderChunks = value
		case "SctpFragUsrMsgs":
			sctp.FragUsrMsgs = value
		case "SctpReasmUsrMsgs":
			sctp.ReasmUsrMsgs = value
		case "SctpOutSCTPPacks":
			sctp.OutSCTPPacks = value
		case "SctpInSCTPPacks":
			sctp.InSCTPPacks = value
		case "SctpT1InitExpireds":
			sctp.T1InitExpireds = value
		case "SctpT1CookieExpireds":
			sctp.T1CookieExpireds = value
		case "SctpT2ShutdownExpireds":
			sctp.T2ShutdownExpireds = value
		case "SctpT3RtxExpireds":
			sctp.T3RtxExpireds = value
		case "SctpT4RtoExpireds":
			sctp.T4RtoExpireds = value
		case "SctpT5ShutdownGuardExpireds":
			sctp.T5ShutdownGuardExpireds = value
		case "SctpDelaySackExpireds":
			sctp.DelaySackExpireds = value
		case "SctpAutocloseExpireds":
			sctp.AutocloseExpireds = value
		case "SctpT3Retransmits":
			sctp.T3Retransmits = value
		case "SctpPmtudRetransmits":
			sctp.PmtudRetransmits = value
		case "SctpFastRetransmits":
			sctp.FastRetransmits = value
		case "SctpInPktSoftirq":
			sctp.InPktSoftirq = value
		case "SctpInPktBacklog":
			sctp.InPktBacklog = value
		case "SctpInPktDiscards":
			sctp.InPktDiscards = value
		case "SctpInDataChunkDiscards":
			sctp.InDataChunkDiscards = value
		default:
			return nil, fmt.Errorf("invalid sctp metric")
		}
	}

	return sctp, scanner.Err()
}
