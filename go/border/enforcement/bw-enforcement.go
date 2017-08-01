// Copyright 2016 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file contains all logic to do the bandwidth enforcement within
// the router.

package enforcement

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"time"
)

type BWEnforcer struct {
	// DoEnforcement indicates whether to do enforcement or not.
	DoEnforcement bool
	// Interfaces contains all interfaces that have ASes with
	// reserved bandwidth.
	Interfaces map[common.IFIDType]IFEContainer
}

// IFEContainer contains all information that is necessary to do
// bandwidth enforcement per interface.
type IFEContainer struct {
	// avgs holds all averages associated to an AS.
	avgs map[uint32]*ASEInformation
	// maxIfBw indicates the maximum bandwidth for the interface
	// either ingress or egress
	maxIfBw int64
	// usedIfBw holds the currently used BW by all reserved ASes.
	usedIfBw int64
	// tUsedIfBw is the time stamp at which the usedIfBw was last updated.
	tUsedIfBw time.Time
	//unknown holds the current average for unknown ASes.
	unknown ASEInformation
}

// ASEInformation contains all information necessary to do bandwidth
// enforcement for a certain AS.
type ASEInformation struct {
	// maxBw indicates the max bandwidth that the AS is allowed to use.
	maxBw int64
	// alertBW indicates the bandwidth that is used for alerting. currently it is set to 95%.
	alertBW int64
	// curBw holds the current used BW of the AS.
	curBw int64
	// movAvg holds the current bandwidth average of the AS.
	movAvg *MovingAverage
	// Labels holds the prometheus labels of the AS.
	Labels prometheus.Labels
}

// Check() indicates whether a packet should be forwarded to the next stage
// of the router or not.
func (bwe *BWEnforcer) Check(rp *rpkt.RtrPkt) bool {
	ifid, _ := rp.IFCurr()
	if ifInfo, ex := bwe.Interfaces[*ifid]; ex {
		srcIA, _ := rp.SrcIA()
		length := len(rp.Raw)
		return ifInfo.canForward(srcIA, length)
	}
	return true
}

// canForward() indicates whether a packet is allowed to pass the router. It is not if
// the AS exceeds its bandwidth limit.
func (ifec *IFEContainer) canForward2(isdas *addr.ISD_AS, length int) bool {
	info := ifec.getBWInfo(*isdas)
	labels := info.Labels

	//If there is unlimited BW for an AS just forward the packet.
	if info.maxBw == -1 {
		return true
	}

	//If there is no BW assigned to an AS just drop the packet.
	if info.maxBw == 0 {
		return false
	}

	avg := info.getAvg()
	if avg < info.maxBw {
		info.addPktToAvg2(length)
		if avg > info.alertBW {
			metrics.CurBwPerAs.With(labels).Set(float64(avg))
		}

		return true
	}

	metrics.CurBwPerAs.With(labels).Set(float64(avg))
	metrics.PktsDropPerAs.With(labels).Inc()
	return false
}

// canForward() indicates whether a packet is allowed to pass the router. It is not if
// the AS exceeds its bandwidth limit.
func (ifec *IFEContainer) canForward(isdas *addr.ISD_AS, length int) bool {
	asInfo, exists := ifec.getBWInfo(*isdas)
	if exists {
		oldAsBw, curAsBw := asInfo.getAvgs(false)
		if curAsBw < asInfo.maxBw {
			asInfo.addPktToAvg(length, false)
			ifec.usedIfBw -= oldAsBw
			ifec.usedIfBw += curAsBw
			return true
		}
	} else {
		_, curAsBw := asInfo.getAvgs(true)
		freeIfBw := ifec.maxIfBw - ifec.getUsedIfBw()
		// 0.75 * maxIFBw && (curAsBw < maxAsBw || curAsBw < freeIfBw )
		flag := (curAsBw < (ifec.maxIfBw >> 1 + ifec.maxIfBw >> 2)) && (curAsBw < asInfo.maxBw || curAsBw < freeIfBw)
		if flag {
			asInfo.addPktToAvg(length, true)
			return true
		}
	}

	metrics.CurBwPerAs.With(labels).Set(float64(avg))
	metrics.PktsDropPerAs.With(labels).Inc()
	return false
}

func (ifec *IFEContainer) getUsedIfBw() int64 {
	eT := time.Since(ifec.tUsedIfBw)

	if eT.Seconds() >= 5 {
		usedIfBw := int64(0)
		for _, avg := range ifec.avgs {
			_, curBw := avg.getAvgs(false)
			usedIfBw += curBw
		}
		ifec.tUsedIfBw = time.Now()
	}

	return ifec.usedIfBw
}

// getBWInfo() checks if there is a moving average for addr and returns it. If not it
// returns the moving average for unknown ASes.
func (ifec *IFEContainer) getBWInfo(addr addr.ISD_AS) ASEInformation {
	info, exists := ifec.avgs[addr.Uint32()]
	if exists {
		return *info, true
	}
	return ifec.unknown, false
}

// getAvg() returns the current moving average in bits.
func (info *ASEInformation) getAvg() int64 {
	return info.movAvg.getAverage() * 8
}

func (info *ASEInformation) getAvgs(unknown bool) (int64, int64) {
	if !unknown && info.maxBw == 0 {
		return 0, 0
	}
	oldBw := info.curBw
	info.curBw = info.movAvg.getAverage() * 8
	return oldBw, info.curBw
}

// addPktToAvg() adds the packet to the moving average
func (info *ASEInformation) addPktToAvg(length int, unknown bool) {
	if info.maxBw != 0 || unknown {
		info.movAvg.add(length)
	}
}

// addPktToAvg() adds the length of the packet in bytes to the moving average.
func (info *ASEInformation) addPktToAvg2(length int) {
	info.movAvg.add(length)
}
