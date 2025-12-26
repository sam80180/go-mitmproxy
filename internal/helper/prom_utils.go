package helper

import (
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

func SumCounterVec(cv *prometheus.CounterVec) float64 {
	ch := make(chan prometheus.Metric)
	go (func() {
		cv.Collect(ch)
		close(ch)
	})()
	var sum float64
	for m := range ch {
		dto := &io_prometheus_client.Metric{}
		if err := m.Write(dto); err != nil {
			continue
		} // end if
		if dto.Counter != nil {
			sum += dto.Counter.GetValue()
		} // end if
	} // end for
	return sum
} // end SumCounterVec()

func GetCounterValue(cv *prometheus.CounterVec, labels ...string) (float64, error) {
	counter, err := cv.GetMetricWithLabelValues(labels...) // get the specific counter within the vec
	if err != nil {
		return 0, err
	} // end if
	var metric io_prometheus_client.Metric // prepare a DTO to read into
	if err := counter.Write(&metric); err != nil {
		return 0, err
	} // end if
	return metric.GetCounter().GetValue(), nil // extract value
} // end GetCounterValue()
