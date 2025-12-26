package helper

import (
	"reflect"
	"unsafe"
)

// GetField[T] returns the value of the struct field named `field` as T.
// Works for exported and unexported fields. If x is not a struct (or pointer to),
// or the field can't be found / can't be shaped into T, it returns the zero T and false.
//
// ⚠️ Uses unsafe; fragile across Go versions and may break under certain flags.
func GetField[T any](x any, field string) (T, bool) {
	var zero T

	v := reflect.ValueOf(x)
	if !v.IsValid() {
		return zero, false
	}

	// Deref pointers
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return zero, false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return zero, false
	}

	// Find the field (promoted fields included)
	f := v.FieldByName(field)
	if !f.IsValid() {
		return zero, false
	}

	// Ensure addressability for unsafe access. If the original isn't addressable,
	// make an addressable copy and re-grab the field from there.
	if !f.CanAddr() {
		av := reflect.New(v.Type()).Elem()
		av.Set(v)
		f = av.FieldByName(field)
	}

	// For exported fields, f.Interface() would work—but for unexported it panics.
	// Use unsafe path that works for both.
	ptr := unsafe.Pointer(f.UnsafeAddr())
	rf := reflect.NewAt(f.Type(), ptr).Elem()
	val := rf.Interface()

	want := reflect.TypeOf((*T)(nil)).Elem()
	got := reflect.TypeOf(val)

	// Fast-path: exact/assignable
	if got.AssignableTo(want) {
		return val.(T), true
	}
	// If T is an interface and the value implements it
	if want.Kind() == reflect.Interface && got.Implements(want) {
		return val.(T), true
	}
	// Convertible (e.g., defined types)
	if got.ConvertibleTo(want) {
		return reflect.ValueOf(val).Convert(want).Interface().(T), true
	}

	return zero, false
}
