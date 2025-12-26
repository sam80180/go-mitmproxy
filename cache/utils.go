package cache

import (
	"fmt"
	"reflect"

	"github.com/datasapiens/cachier"
)

func GetOrCompute[T any](cache *cachier.Cache[any], key string, getter func() (*any, error)) (*T, error) {
	ptrVal, errGet := cache.GetOrCompute(key, getter)
	if errGet != nil {
		return nil, errGet
	} // end if
	if ptrVal == nil {
		return nil, nil
	} // end if
	if castedVal, ok := (*ptrVal).(T); !ok {
		var dummy T
		return nil, fmt.Errorf("cannot cast value of type '%s' to '%s'", reflect.TypeOf(*ptrVal), reflect.TypeOf(dummy))
	} else {
		return &castedVal, nil
	} // end if
} // end GetOrCompute()
