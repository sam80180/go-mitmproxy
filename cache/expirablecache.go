package cache

import (
	"fmt"
	"time"

	expirablecache "github.com/go-pkgz/expirable-cache/v3"
)

type PkgzExpirableCache struct {
	cache expirablecache.Cache[string, any]
} // end type

func NewPkgzExpirableCache(maxKeys int, ttl time.Duration, isLRU bool) (*PkgzExpirableCache, error) {
	c := expirablecache.NewCache[string, any]()
	if maxKeys > 0 {
		c.WithMaxKeys(maxKeys)
	} // end if
	if ttl > 0 {
		c.WithTTL(ttl)
	} // end if
	if isLRU {
		c.WithLRU()
	} // end if
	return &PkgzExpirableCache{cache: c}, nil
} // end NewPkgzExpirableCache()

func (rc *PkgzExpirableCache) setWithTTL(key string, value any, ttl time.Duration) error {
	rc.cache.Set(key, value, ttl)
	return nil
} // end setWithTTL()

/****************** cachier interface functions ******************/
func (rc *PkgzExpirableCache) Get(key string) (any, error) {
	val, bHas := rc.cache.Get(key)
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

func (rc *PkgzExpirableCache) Peek(key string) (any, error) {
	return rc.Peek(key)
} // end Peek()

func (rc *PkgzExpirableCache) Set(key string, value any) error {
	if ptr, bOk := value.(*any); bOk {
		if valWithTtl, ok := (*ptr).(ValueWithTTL); ok {
			return rc.setWithTTL(key, value, valWithTtl.TTL)
		} // end if
	} // end if
	return rc.setWithTTL(key, value, 0*time.Nanosecond)
} // end Set()

func (rc *PkgzExpirableCache) Delete(key string) error {
	rc.cache.Remove(key)
	return nil
} // end Delete()

func (rc *PkgzExpirableCache) Keys() ([]string, error) {
	return rc.cache.Keys(), nil
} // end Keys()

func (rc *PkgzExpirableCache) Purge() error {
	rc.cache.Purge()
	return nil
} // end Purge()
