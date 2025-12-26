package helper

import (
	"encoding/json"

	"github.com/go-viper/mapstructure/v2"
)

func JSONCustomTagMarshal(v any, tag, flagDelimiter string) ([]byte, error) {
	data := StructToMap(v, tag, flagDelimiter)
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	} // end if
	return jsonBytes, nil
} // end JSONCustomTagMarshal()

func JSONCustomTagUnmarshal[T any](data any, tag string, hook mapstructure.DecodeHookFunc, outVar *T) error {
	decoderConfig := &mapstructure.DecoderConfig{
		Result:  outVar,
		TagName: tag,
	}
	if hook != nil {
		decoderConfig.DecodeHook = hook
	} // end if
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return err
	} // end if
	return decoder.Decode(data)
} // end JSONCustomTagUnmarshal()
