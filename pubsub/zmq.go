package pubsub

import (
	"context"
	"encoding/json"

	watermillmsg "github.com/ThreeDotsLabs/watermill/message"
	"github.com/go-zeromq/zmq4"
	"github.com/hetiansu5/urlquery"
	"github.com/sirupsen/logrus"
)

type ZmqPubSubOptions struct {
	Address string `query:"address"`
} // end type

func (opts *ZmqPubSubOptions) QueryEncode() []byte {
	b, _ := urlquery.Marshal(opts)
	return b
} // end QueryEncode()

func DefaultZmqPubSubOptions() ZmqPubSubOptions {
	return ZmqPubSubOptions{Address: "tcp://127.0.0.1:5563"}
} // end DefaultZmqPubSubOptions()

type ZmqPub struct {
	socket zmq4.Socket
} // end type

func NewZmqPub(opts ZmqPubSubOptions) (*ZmqPub, error) {
	pub := zmq4.NewPub(context.Background())
	err := pub.Listen(opts.Address)
	return &ZmqPub{socket: pub}, err
} // end NewZmqPub()

func (z *ZmqPub) Publish(topic string, messages ...*watermillmsg.Message) error {
	topicBytes := []byte(topic)
	for _, msg := range messages {
		b, e := json.Marshal(msg)
		if e != nil {
			return e
		} // end if
		msgA := zmq4.NewMsgFrom(topicBytes, b)
		if errSnd := z.socket.SendMulti(msgA); errSnd != nil {
			return errSnd
		} // end if
	} // end for
	return nil
} // end Publish()

func (z *ZmqPub) Close() error {
	return z.socket.Close()
} // end Close()

type ZmqSub struct {
	socket zmq4.Socket
} // end type

func NewZmqSub(opts ZmqPubSubOptions) (*ZmqSub, error) {
	sub := zmq4.NewSub(context.Background())
	err := sub.Dial(opts.Address)
	return &ZmqSub{socket: sub}, err
} // end NewZmqSub()

func (z *ZmqSub) Subscribe(ctx context.Context, topic string) (<-chan *watermillmsg.Message, error) {
	z.socket.SetOption(zmq4.OptionSubscribe, topic)
	outputChannel := make(chan *watermillmsg.Message, 100)
	go (func(ch chan<- *watermillmsg.Message) {
		for {
			msg, err := z.socket.Recv()
			if err != nil {
				logrus.Warn(err)
				break
			} // end if
			if len(msg.Frames) > 1 {
				var wmsg watermillmsg.Message
				if err = json.Unmarshal([]byte(msg.Frames[1]), &wmsg); err != nil {
					logrus.Warn(err)
					continue
				} // end if
				ch <- &wmsg
			} // end if
		}
	})(outputChannel)
	return outputChannel, nil
} // end Subscribe()

func (z *ZmqSub) Close() error {
	return z.socket.Close()
} // end Close()
