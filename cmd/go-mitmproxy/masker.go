package main

import (
	"flag"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"

	myipc "github.com/lqqyt2423/go-mitmproxy/ipc"
	mymetrics "github.com/lqqyt2423/go-mitmproxy/metrics"
	mask "github.com/showa-93/go-mask"
)

func mask_proc_title() {
	maskFn := map[string]func(string) (any, error){
		"metrics_exporter": func(s string) (any, error) {
			metricsOptions := mymetrics.ParseMetricsOptions(s)
			maskValue, _ := mask.Mask(metricsOptions)
			b := maskValue.QueryEncode()
			return string(b), nil
		},
		"proxyauth": func(input string) (any, error) {
			re := regexp.MustCompile(`([^:|]+):([^:|]+)`)
			matches := re.FindAllStringSubmatch(input, -1)
			usernames := []string{}
			for _, m := range matches {
				usernames = append(usernames, m[1])
			} // end for
			return strings.Join(usernames, "|"), nil
		},
		"ipc": func(s string) (any, error) {
			opts := myipc.ParseIPCOptions(s)
			return opts.Endpoint, nil
		},
	}
	bIsTampered := false
	args := slices.Clone(os.Args)
	flag.VisitAll(func(f *flag.Flag) {
		if "*flag.boolValue" == reflect.TypeOf(f.Value).String() {
			return
		} // end if
		for i, argv := range os.Args {
			if argv == "--" {
				break
			} // end for
			argIndex := -1
			argValue := ""
			if regexp.MustCompile(fmt.Sprintf("^-?-%s$", regexp.QuoteMeta(f.Name))).MatchString(argv) { // value at next argument
				argIndex = i + 1
				argValue = os.Args[argIndex]
			} else if regexp.MustCompile(fmt.Sprintf("^-?-%s=.*", regexp.QuoteMeta(f.Name))).MatchString(argv) { // has value
				argIndex = i
				argValue = strings.TrimLeft(argv, "-")
				argValue = argValue[len(f.Name)+1:]
			} else {
				continue
			} // end if
			if argIndex < 0 {
				continue
			} // end if
			if fn, has := maskFn[f.Name]; has {
				maskedValue, errMask := fn(argValue)
				if errMask != nil || maskedValue == argValue {
					continue
				} // end if
				if i == argIndex { // has value
					args[argIndex] = fmt.Sprintf("-%s=%+v", f.Name, maskedValue)
				} else {
					args[argIndex] = fmt.Sprintf("%+v", maskedValue)
				} // end if
				bIsTampered = true
			} // end if
		} // end for
	})
	if bIsTampered {
		setproctitle(strings.Join(args, " "))
	} // end if
} // end mask_proc_title()
