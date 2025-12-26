package cache

import (
	"fmt"
	"time"

	ristretto "github.com/dgraph-io/ristretto/v2"
)

type RistrettoCache struct {
	store *ristretto.Cache[string, any]
} // end type

func NewRistrettoCache(maxKeys int64) (*RistrettoCache, error) {
	cache, errCache := ristretto.NewCache(&ristretto.Config[string, any]{
		NumCounters: maxKeys, // number of keys to track frequency of (10M).
		MaxCost:     1 << 30, // maximum cost of cache (1GB).
		BufferItems: 64,      // number of keys per Get buffer.
	})
	if errCache != nil {
		return nil, errCache
	} // end if
	return &RistrettoCache{store: cache}, nil
} // end NewRistrettoCache()

func (rc *RistrettoCache) setWithTTL(key string, value any, ttl time.Duration) error {
	if !rc.store.SetWithTTL(key, value, 1, ttl) {
		return fmt.Errorf("dropped")
	} // end if
	return nil
} // end setWithTTL()

/****************** cachier interface functions ******************/
func (rc *RistrettoCache) Get(key string) (any, error) {
	val, bHas := rc.store.Get(key)
	if bHas {
		if ptr, bOk := val.(*any); bOk {
			if valWithTtl, ok := (*ptr).(ValueWithTTL); ok {
				valWithTtl.Hit = true
				var vv any = valWithTtl
				return &vv, nil
			} // end if
		} // end if
		return val, nil
	} // end if
	return nil, fmt.Errorf("not found")
} // end Get()

func (rc *RistrettoCache) Peek(key string) (any, error) {
	return rc.Get(key)
} // end Peek()

func (rc *RistrettoCache) Set(key string, value any) error {
	if ptr, bOk := value.(*any); bOk {
		if valWithTtl, ok := (*ptr).(ValueWithTTL); ok {
			return rc.setWithTTL(key, value, valWithTtl.TTL)
		} // end if
	} // end if
	return rc.setWithTTL(key, value, 0*time.Nanosecond)
} // end Set()

func (rc *RistrettoCache) Delete(key string) error {
	rc.store.Del(key)
	return nil
} // end Delete()

func (rc *RistrettoCache) Keys() ([]string, error) {
	return nil, nil
} // end Keys()

func (rc *RistrettoCache) Purge() error {
	rc.store.Clear()
	return nil
} // end Purge()
