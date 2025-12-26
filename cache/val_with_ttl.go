package cache

import (
	"fmt"
	"reflect"
	"time"

	"github.com/datasapiens/cachier"
)

type ValueWithTTL struct {
	Value    any            `json:"value"`
	TTL      time.Duration  `json:"ttl"`
	Hit      bool           `json:"-"`
	Metadata map[string]any `json:"metadata"`
} // end type

func UnwrapValueWithTTL[T any](v *any) (castedVal *T, bHit bool, errCast error) {
	if valWithTtl, ok := (*v).(ValueWithTTL); ok {
		bHit = valWithTtl.Hit
		if vv, ok := valWithTtl.Value.(T); !ok {
			var dummy T
			errCast = fmt.Errorf("cannot cast value of type '%s' to '%s'", reflect.TypeOf(*v), reflect.TypeOf(dummy))
		} else {
			castedVal = &vv
		} // end if
	} else {
		errCast = fmt.Errorf("not a '%s'", reflect.TypeOf(ValueWithTTL{}))
	} // end if
	return
} // end UnwrapValueWithTTL()

func GetOrComputeValueWithTTL[T any](cache *cachier.Cache[any], key string, getter func() (*any, error), ttl time.Duration) (*T, bool, error) {
	wrapped_getter := func() (*any, error) {
		ptr, e := getter()
		if e != nil {
			return nil, e
		} // end if
		var v any = nil
		if ptr != nil {
			v = *ptr
		} // end if
		var valWithTtl any = ValueWithTTL{Value: v, TTL: ttl}
		return &valWithTtl, nil
	}
	v, errGet := GetOrCompute[any](cache, key, wrapped_getter)
	if errGet != nil {
		return nil, false, errGet
	} // end if
	return UnwrapValueWithTTL[T](v)
} // end GetOrCompute()

func SetValueWithTtl(cache *cachier.Cache[any], k string, v any, ttl time.Duration) {
	var valWithTtl any = ValueWithTTL{Value: v, TTL: ttl}
	cache.Set(k, &valWithTtl)
} // end SetValueWithTtl()
