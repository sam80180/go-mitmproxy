package helper

import (
	"context"
	"reflect"
	"time"
)

func DrainChannelsWithTimeout[T any](ctx context.Context, chans []<-chan T, perDrainTimeout time.Duration, cbOnChannelData func(T, int), cbOnChannelEmpty, cbOnChannelClose, cbOnTimeout func(int), cbOnCancel func()) {
	cases := make([]reflect.SelectCase, len(chans)+1)
	cases[0] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ctx.Done())} // Fairness is pseudo-random; over many iterations, each ready channel will get selected roughly equally.
	for i, ch := range chans {
		cases[i+1] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ch)}
	} // end for
	for {
		chosen, recv, ok := reflect.Select(cases)
		if chosen == 0 {
			if cbOnCancel != nil {
				cbOnCancel()
			} // end if
			return
		} // end if
		chIdx := chosen - 1
		if !ok {
			if cbOnChannelClose != nil {
				cbOnChannelClose(chIdx)
			} // end if
			cases[chosen].Chan = reflect.ValueOf(nil)
			continue
		} // end if
		timer := time.NewTimer(perDrainTimeout) // Per-channel timer
		val := recv.Interface().(T)             // read first value
		if cbOnChannelData != nil {
			cbOnChannelData(val, chIdx)
		} // end if
	drainLoop:
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				if cbOnCancel != nil {
					cbOnCancel()
				} // end if
				return
			case v, ok := <-chans[chIdx]:
				if !ok {
					if cbOnChannelClose != nil {
						cbOnChannelClose(chIdx)
					} // end if
					break drainLoop
				} // end if
				if cbOnChannelData != nil {
					cbOnChannelData(v, chIdx)
				} // end if
			case <-timer.C:
				if cbOnTimeout != nil {
					cbOnTimeout(chIdx)
				} // end if
				break drainLoop
			default:
				if cbOnChannelEmpty != nil {
					cbOnChannelEmpty(chIdx)
				} // end if
				break drainLoop
			} // end switch
		} // end for
		timer.Stop()
	} // end for
} // end drainWithTimeout()
