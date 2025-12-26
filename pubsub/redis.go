package pubsub

import (
	"context"
	"encoding/json"

	watermillmsg "github.com/ThreeDotsLabs/watermill/message"
	redis "github.com/go-redis/redis/v8"
	"github.com/hetiansu5/urlquery"
	"github.com/sirupsen/logrus"
)

type RedisPubSubOptions struct {
	URL string `query:"url"`
} // end type

func (opts *RedisPubSubOptions) QueryEncode() []byte {
	b, _ := urlquery.Marshal(opts)
	return b
} // end QueryEncode()

func DefaultRedisPubSubOptions() RedisPubSubOptions {
	return RedisPubSubOptions{URL: "redis://localhost:6379/0"}
} // end DefaultRedisPubSubOptions()

type RedisPub struct {
	client *redis.Client
} // end type

func newRedisClient(url string) (*redis.Client, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	} // end if
	return redis.NewClient(opts), nil
} // end newRedisClient()

func NewRedisPub(opts RedisPubSubOptions) (*RedisPub, error) {
	client, err := newRedisClient(opts.URL)
	if err != nil {
		return nil, err
	} // end if
	return &RedisPub{client: client}, nil
} // end NewRedisPub()

func (r *RedisPub) Publish(topic string, messages ...*watermillmsg.Message) error {
	ctx := context.Background()
	for _, msg := range messages {
		b, e := json.Marshal(msg)
		if e != nil {
			return e
		} // end if
		r.client.Publish(ctx, topic, b)
	} // end for
	return nil
} // end Publish()

func (r *RedisPub) Close() error {
	return r.client.Close()
} // end Close()

type RedisSub struct {
	client *redis.Client
} // end type

func NewRedisSub(opts RedisPubSubOptions) (*RedisSub, error) {
	client, err := newRedisClient(opts.URL)
	if err != nil {
		return nil, err
	} // end if
	return &RedisSub{client: client}, nil
} // end NewRedisSub()

func (r *RedisSub) Subscribe(ctx context.Context, topic string) (<-chan *watermillmsg.Message, error) {
	subscription := r.client.Subscribe(ctx, topic)
	outputChannel := make(chan *watermillmsg.Message, 100)
	go (func(ch chan<- *watermillmsg.Message) {
		for {
			msg, err := subscription.ReceiveMessage(ctx)
			if err != nil {
				logrus.Warn(err)
				break
			} // end if
			var wmsg watermillmsg.Message
			if err = json.Unmarshal([]byte(msg.Payload), &wmsg); err != nil {
				logrus.Warn(err)
				continue
			} // end if
			ch <- &wmsg
		} // end for
		subscription.Close()
		r.Close()
	})(outputChannel)
	return outputChannel, nil
} // end Subscribe()

func (r *RedisSub) Close() error {
	return r.client.Close()
} // end Close()
