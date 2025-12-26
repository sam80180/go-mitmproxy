package pubsub

import (
	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/pubsub/gochannel"
)

func NewGoChannelPubSub() *gochannel.GoChannel {
	// 當-syslog='type=beat'時，這裡也用logrus會卡住
	logger := watermill.NewStdLogger(false, false)
	return gochannel.NewGoChannel(gochannel.Config{Persistent: false, BlockPublishUntilSubscriberAck: false, OutputChannelBuffer: 100}, logger)
} // end NewGoChannelPubSub()
