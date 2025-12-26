package helper

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
)

func StructFieldAllTags(field reflect.StructField) map[string]string { // https://github.com/golang/go/blob/master/src/reflect/type.go#L1049
	tag := fmt.Sprintf("%+v", field.Tag)
	tagKeyValPairs := map[string]string{}
	for tag != "" {
		// Skip leading space.
		i := 0
		for i < len(tag) && tag[i] == ' ' {
			i++
		}
		tag = tag[i:]
		if tag == "" {
			break
		}

		// Scan to colon. A space, a quote or a control character is a syntax error.
		// Strictly speaking, control chars include the range [0x7f, 0x9f], not just
		// [0x00, 0x1f], but in practice, we ignore the multi-byte control characters
		// as it is simpler to inspect the tag's bytes than the tag's runes.
		i = 0
		for i < len(tag) && tag[i] > ' ' && tag[i] != ':' && tag[i] != '"' && tag[i] != 0x7f {
			i++
		}
		if i == 0 || i+1 >= len(tag) || tag[i] != ':' || tag[i+1] != '"' {
			break
		}
		name := string(tag[:i])
		tag = tag[i+1:]

		// Scan quoted string to find value.
		i = 1
		for i < len(tag) && tag[i] != '"' {
			if tag[i] == '\\' {
				i++
			}
			i++
		}
		if i >= len(tag) {
			break
		}
		qvalue := string(tag[:i+1])
		tag = tag[i+1:]

		vv, _ := strconv.Unquote(qvalue)
		tagKeyValPairs[name] = vv
	}
	return tagKeyValPairs
} // end StructFieldAllTags()

func StructToMap(obj any, tagName, flagDelimiter string) map[string]any {
	result := make(map[string]any)
	t := reflect.TypeOf(obj)
	v := reflect.ValueOf(obj)
	if t.Kind() == reflect.Ptr { // handle pointers by dereferencing
		t = t.Elem()
		v = v.Elem()
	} // end if
	if t.Kind() != reflect.Struct {
		return result
	} // end if
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)
		tag := field.Tag.Get(tagName)
		if tag == "" || tag == "-" {
			continue
		} // end if
		if len(flagDelimiter) > 0 {
			tag = strings.Split(tag, flagDelimiter)[0]
		} // end if
		if value.Kind() == reflect.Struct { // handle nested structs recursively
			nestedMap := StructToMap(value.Interface(), tagName, flagDelimiter)
			if len(nestedMap) > 0 {
				result[tag] = nestedMap
			} // end if
		} else if value.Kind() == reflect.Ptr && !value.IsNil() && value.Elem().Kind() == reflect.Struct {
			nestedMap := StructToMap(value.Elem().Interface(), tagName, flagDelimiter)
			if len(nestedMap) > 0 {
				result[tag] = nestedMap
			} // end if
		} else { // normal field processing
			result[tag] = value.Interface()
		} // end if
	} // end for
	return result
} // end StructToMap()

func ValidOrPanic(s any) {
	validate := validator.New(validator.WithRequiredStructEnabled())
	if errValidat := validate.Struct(s); errValidat != nil {
		var validateErrs validator.ValidationErrors
		if errors.As(errValidat, &validateErrs) {
			for _, validateErr := range validateErrs {
				/*
					if validateErr.ActualTag() == "oneof" {
						panic(fmt.Sprintf("%s has invalid value, must be: %+v", validateErr.Namespace(), validateErr.Param()))
					} // end if
				*/
				panic(fmt.Errorf("%+v: param= %+v", validateErr, validateErr.Param()))
			} // end if
		} // end if
	} // end if
} // end ValidOrPanic()
