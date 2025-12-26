package sflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"

	sflow_record "github.com/fstelzer/sflow/records"
	"github.com/jinzhu/copier"
	"github.com/lunixbochs/struc"
)

type myHTTPRequestFlowRecord struct {
	record sflow_record.Record
} // end type

func newMyHTTPRequestFlowRecord(record sflow_record.HTTPRequestFlow) sflow_record.Record {
	return &myHTTPRequestFlowRecord{record: record}
} // end newMyHTTPRequestFlowRecord()

func (r *myHTTPRequestFlowRecord) RecordType() int {
	return r.record.RecordType()
} // end RecordType()

func (r *myHTTPRequestFlowRecord) RecordName() string {
	return r.record.RecordName()
} // end RecordName()

func (r *myHTTPRequestFlowRecord) Encode(w io.Writer) error {
	v := reflect.ValueOf(r.record)
	fields := []reflect.StructField{}
	typeByteArr := reflect.TypeOf([]byte{})
	kindByteArr := typeByteArr.Kind()
	const stringFieldLengthSuffix = "Len"
	mPaddings := map[string]int{}
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if strings.HasSuffix(field.Name, stringFieldLengthSuffix) {
			strActualFieldName := field.Name[:len(field.Name)-len(stringFieldLengthSuffix)]
			field.Tag += reflect.StructTag(fmt.Sprintf(`struc:"sizeof=%s"`, strActualFieldName))

			// padding (https://datatracker.ietf.org/doc/html/rfc4506?utm_source=chatgpt.com#section-4.11)
			if actualField := v.FieldByName(strActualFieldName); actualField.IsValid() && actualField.Type().Kind() == kindByteArr {
				actualLength := len(actualField.Interface().([]byte))
				if padSize := 4 - (actualLength % 4); padSize > 0 {
					mPaddings[strActualFieldName] = padSize
				} // end if
			} // end if
		} // end if
		fields = append(fields, field)
		if padSize, has := mPaddings[field.Name]; has { // add padding byte by byte (avoid problem when padSize is 3)
			tag := reflect.StructTag(`struc:"pad"`)
			typePad := reflect.TypeOf(byte(0))
			for i := 0; i < padSize; i++ {
				fields = append(fields, reflect.StructField{
					Name: fmt.Sprintf("%sPad%d", field.Name, i+1),
					Type: typePad,
					Tag:  tag,
				})
			} // end for
			delete(mPaddings, field.Name)
		} // end if
	} // end if
	dynamicType := reflect.StructOf(fields)
	instance := reflect.New(dynamicType).Interface()
	if errCopy := copier.Copy(instance, r.record); errCopy != nil {
		return errCopy
	} // end if
	var bufPayload bytes.Buffer
	if errPack := struc.Pack(&bufPayload, instance); errPack != nil {
		return errPack
	} // end if
	bufHead := make([]byte, 8)
	binary.BigEndian.PutUint32(bufHead[0:4], uint32(r.record.RecordType()))
	binary.BigEndian.PutUint32(bufHead[4:8], uint32(bufPayload.Len()))
	if _, errW := w.Write(bufHead); errW != nil {
		return errW
	} // end if
	_, errW := w.Write(bufPayload.Bytes())
	return errW
} // end Encode()

type myExtendedSocketIPv4Flow struct {
	record sflow_record.Record
} // end type

func newMyExtendedSocketIPv4Flow(record sflow_record.ExtendedSocketIPv4Flow) sflow_record.Record {
	return &myExtendedSocketIPv4Flow{record: record}
} // end newMyExtendedSocketIPv4Flow()

func (r *myExtendedSocketIPv4Flow) RecordType() int {
	return r.record.RecordType()
} // end RecordType()

func (r *myExtendedSocketIPv4Flow) RecordName() string {
	return r.record.RecordName()
} // end RecordName()

func (r *myExtendedSocketIPv4Flow) Encode(w io.Writer) error {
	v := reflect.ValueOf(r.record)
	fields := []reflect.StructField{}
	kindNetIP := reflect.TypeOf(net.IP{}).Kind()
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if field.Type.Kind() == kindNetIP {
			field.Tag = `struc:"[4]byte"`
		} // end if
		fields = append(fields, field)
	} // end if
	dynamicType := reflect.StructOf(fields)
	instance := reflect.New(dynamicType).Interface()
	if errCopy := copier.Copy(instance, r.record); errCopy != nil {
		return errCopy
	} // end if
	var bufPayload bytes.Buffer
	if errPack := struc.Pack(&bufPayload, instance); errPack != nil {
		return errPack
	} // end if
	bufHead := make([]byte, 8)
	binary.BigEndian.PutUint32(bufHead[0:4], uint32(r.record.RecordType()))
	binary.BigEndian.PutUint32(bufHead[4:8], uint32(bufPayload.Len()))
	if _, errW := w.Write(bufHead); errW != nil {
		return errW
	} // end if
	_, errW := w.Write(bufPayload.Bytes())
	return errW
} // end Encode()

type myExtendedSocketIPv6Flow struct {
	record sflow_record.Record
} // end type

func newMyExtendedSocketIPv6Flow(record sflow_record.ExtendedSocketIPv6Flow) sflow_record.Record {
	return &myExtendedSocketIPv6Flow{record: record}
} // end newMyExtendedSocketIPv6Flow()

func (r *myExtendedSocketIPv6Flow) RecordType() int {
	return r.record.RecordType()
} // end RecordType()

func (r *myExtendedSocketIPv6Flow) RecordName() string {
	return r.record.RecordName()
} // end RecordName()

func (r *myExtendedSocketIPv6Flow) Encode(w io.Writer) error {
	v := reflect.ValueOf(r.record)
	fields := []reflect.StructField{}
	kindNetIP := reflect.TypeOf(net.IP{}).Kind()
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if field.Type.Kind() == kindNetIP {
			field.Tag = `struc:"[16]byte"`
		} // end if
		fields = append(fields, field)
	} // end if
	dynamicType := reflect.StructOf(fields)
	instance := reflect.New(dynamicType).Interface()
	if errCopy := copier.Copy(instance, r.record); errCopy != nil {
		return errCopy
	} // end if
	var bufPayload bytes.Buffer
	if errPack := struc.Pack(&bufPayload, instance); errPack != nil {
		return errPack
	} // end if
	bufHead := make([]byte, 8)
	binary.BigEndian.PutUint32(bufHead[0:4], uint32(r.record.RecordType()))
	binary.BigEndian.PutUint32(bufHead[4:8], uint32(bufPayload.Len()))
	if _, errW := w.Write(bufHead); errW != nil {
		return errW
	} // end if
	_, errW := w.Write(bufPayload.Bytes())
	return errW
} // end Encode()
