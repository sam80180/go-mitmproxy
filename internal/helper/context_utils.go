package helper

import (
	"context"
	"reflect"
	"time"
	"unsafe"
)

type ContextKey string

func IsInstanceOfContextKey(v any) bool {
	return reflect.TypeOf(v).Kind().String() == reflect.TypeOf(ContextKey("")).Kind().String()
} // end IsInstanceOfContextKey()

func ContextWithKeyValuePairs(ctx context.Context, kv map[any]any) context.Context {
	for k, v := range kv {
		ctx = context.WithValue(ctx, k, v)
	} // end for
	return ctx
} // end ContextWithKeyValuePairs()

func ContextAddKey(ctx context.Context, key string, data any) context.Context {
	kk := ContextKey(key)
	return context.WithValue(ctx, kk, data)
} // end ContextAddKey()

func ContextGetKey(ctx context.Context, key string) any {
	kk := ContextKey(key)
	return ctx.Value(kk)
} // end ContextGetKey()

func ContextCopyKeysFn(ctxSrc, ctxDst context.Context, fn func(_, _ any) bool) context.Context {
	kv := ContextKeyValuePairsFn(ctxSrc, fn)
	return ContextWithKeyValuePairs(ctxDst, kv)
} // end ContextCopyKeysFn()

func ContextCopyKeys(ctxSrc, ctxDst context.Context) context.Context {
	return ContextCopyKeysFn(ctxSrc, ctxDst, nil)
} // end ContextCopyKeys()

/*
returns a new context that:
  - has the same WithValue key/value pairs,
  - has the same deadline (if any),
  - will be cancelled when the original is cancelled (propagated),
  - can be cancelled independently by calling the returned cancel func.
*/
func CloneContextFullyFn(orig context.Context, fn func(_, _ any) bool) (context.Context, context.CancelFunc) {
	values := ContextKeyValuePairsFn(orig, fn)
	deadline, hasDeadline := extractContextDeadlineUnsafe(orig)

	// build base context with same deadline (if any)
	var base context.Context
	var baseCancel context.CancelFunc
	if hasDeadline {
		base, baseCancel = context.WithDeadline(context.Background(), deadline)
	} else {
		base = context.Background()
		baseCancel = func() {} // noop
	} // end if

	// reapply values (outermost value applied last so order matches original chain)
	// Note: original chain is valueCtx -> valueCtx -> ... -> cancel/timer -> background
	// We collected values in map (unordered). This means if original used duplicated keys or
	// relied on value shadowing order, that won't be preserved perfectly. For typical use, keys are unique.
	base = ContextWithKeyValuePairs(base, values)

	// wrap with cancel so we can cancel the clone when original cancels
	cloneCtx, cloneCancel := context.WithCancel(base)

	// propagate cancellation: when orig.Done() closes, cancel clone
	go (func() {
		select {
		case <-orig.Done():
			// cancel clone (so clone.Err() is set properly)
			cloneCancel()
		case <-cloneCtx.Done():
			// clone cancelled independently; stop goroutine
		} // end select
		baseCancel() // ensure base timer cancel is called to stop timers if we created one
	})()

	return cloneCtx, func() {
		// user-facing cancel must cancel both clone and base timer (if any)
		cloneCancel()
		baseCancel()
	}
} // end CloneContextFullyFn()

func CloneContextFully(orig context.Context) (context.Context, context.CancelFunc) {
	return CloneContextFullyFn(orig, nil)
} // end CloneContextFully()

func ContextKeyValuePairsFn(ctx context.Context, fn func(_, _ any) bool) map[any]any { // walks the context chain and returns a map of key->value
	result := make(map[any]any)
	for ctx != nil { // recursively walk the chain of contexts
		v := reflect.ValueOf(ctx)
		if v.Kind() == reflect.Ptr && v.Elem().Kind() == reflect.Struct {
			elem := v.Elem()
			t := elem.Type()
			switch t.Name() {
			case "valueCtx":
				// access unexported fields: "Context", "key", "val"
				keyField := elem.FieldByName("key")
				valField := elem.FieldByName("val")
				parentField := elem.FieldByName("Context")

				// use unsafe to read them
				key := reflect.NewAt(keyField.Type(), unsafe.Pointer(keyField.UnsafeAddr())).Elem().Interface()
				val := reflect.NewAt(valField.Type(), unsafe.Pointer(valField.UnsafeAddr())).Elem().Interface()
				if fn == nil || fn(key, val) {
					result[key] = val
				} // end if

				// recurse into parent
				ctx = reflect.NewAt(parentField.Type(), unsafe.Pointer(parentField.UnsafeAddr())).Elem().Interface().(context.Context)
				continue
			case "cancelCtx", "timerCtx":
				// recurse into parent
				parentField := elem.FieldByName("Context")
				ctx = reflect.NewAt(parentField.Type(), unsafe.Pointer(parentField.UnsafeAddr())).Elem().Interface().(context.Context)
				continue
			} // end switch
		} // end if
		break // stop when reaching emptyCtx, cancelCtx, or other non-valueCtx types
	} // end for
	return result
} // end ContextKeyValuePairsFn()

func ContextKeyValuePairs(ctx context.Context) map[any]any {
	return ContextKeyValuePairsFn(ctx, nil)
} // end ContextKeyValuePairs()

func extractContextDeadlineUnsafe(ctx context.Context) (time.Time, bool) { // walks the chain looking for *context.timerCtx and returns its deadline.
	v := reflect.ValueOf(ctx)
	for v.IsValid() {
		typ := v.Type().String()
		switch typ {
		case "*context.timerCtx":
			elem := v.Elem()
			dlField := elem.FieldByName("deadline")
			deadline := reflect.NewAt(dlField.Type(), unsafe.Pointer(dlField.UnsafeAddr())).Elem().Interface().(time.Time) // read the time.Time value using unsafe
			return deadline, true
		case "*context.cancelCtx", "*context.valueCtx":
			elem := v.Elem()
			v = elem.FieldByName("Context")
		default:
			return time.Time{}, false
		} // end switch
	} // end for
	return time.Time{}, false
} // end extractContextDeadlineUnsafe()
