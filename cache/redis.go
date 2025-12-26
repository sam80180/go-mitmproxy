package cache

import (
	"encoding/json"
	"time"

	"github.com/datasapiens/cachier"
	redis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/hetiansu5/urlquery"
	"github.com/lqqyt2423/go-mitmproxy/internal/helper"
	"github.com/sirupsen/logrus"
)

var _ID_ string = uuid.NewString()

type RedisCacheOptions struct {
	URL string `query:"url"`
} // end type

func (opts *RedisCacheOptions) QueryEncode() []byte {
	b, _ := urlquery.Marshal(opts)
	return b
} // end QueryEncode()

func DefaultRedisCacheOptions() RedisCacheOptions {
	return RedisCacheOptions{URL: "redis://localhost:6379/0"}
} // end DefaultRedisCacheOptions()

type RedisCache struct {
	rc     *cachier.RedisCache
	client *redis.Client
} // end type

func NewRedisCache(opts RedisCacheOptions) (*RedisCache, error) {
	redisOpts, err := redis.ParseURL(opts.URL)
	if err != nil {
		return nil, err
	} // end if
	client := redis.NewClient(redisOpts)
	rc := cachier.NewRedisCacheWithLogger(client, "", func(v any) ([]byte, error) {
		return json.Marshal(v)
	}, func(b []byte, v *any) error {
		return json.Unmarshal(b, v)
	}, 0, logrus.StandardLogger(), nil)
	return &RedisCache{rc: rc, client: client}, nil
} // end NewRedisCache()

func (r *RedisCache) setWithTTL(key string, value any, ttl time.Duration) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	} // end if
	if status := r.client.Set(r.client.Context(), key, b, ttl); status != nil {
		return status.Err()
	} // end if
	return nil
} // end setWithTTL()

/****************** cachier interface functions ******************/
func (r *RedisCache) Get(key string) (any, error) {
	val, err := r.rc.Get(key)
	if err != nil {
		return nil, err
	} // end if
	if m, bOk := val.(map[string]any); bOk {
		var valWithTtl ValueWithTTL
		helper.JSONCustomTagUnmarshal(m, "json", nil, &valWithTtl)
		if _id_, has := valWithTtl.Metadata[_ID_]; has && _id_ == _ID_ {
			delete(valWithTtl.Metadata, _ID_)
			valWithTtl.Hit = true
			var vv any = valWithTtl
			return &vv, nil
		} // end if
	} // end if
	return val, nil
} // end Get()

func (r *RedisCache) Peek(key string) (any, error) {
	return r.Get(key)
} // end Peek()

func (r *RedisCache) Set(key string, value any) error {
	if ptr, bOk := value.(*any); bOk {
		if valWithTtl, ok := (*ptr).(ValueWithTTL); ok {
			if valWithTtl.Metadata == nil {
				valWithTtl.Metadata = map[string]any{}
			} // end if
			valWithTtl.Metadata[_ID_] = _ID_ // just to make sure it is an instance of `ValueWithTTL`
			return r.setWithTTL(key, valWithTtl, valWithTtl.TTL)
		} // end if
	} // end if
	return r.rc.Set(key, value)
} // end Set()

func (r *RedisCache) Delete(key string) error {
	return r.rc.Delete(key)
} // end Delete()

func (r *RedisCache) Keys() ([]string, error) {
	return r.rc.Keys()
} // end Keys()

func (r *RedisCache) Purge() error {
	return r.rc.Purge()
} // end Purge()
