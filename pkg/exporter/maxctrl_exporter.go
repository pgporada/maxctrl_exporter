// Copyright 2019, Vitaly Bezgachev, vitaly.bezgachev [the_at_symbol] gmail.com, Kadir Tugan, kadir.tugan [the_at_symbol] gmail.com
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exporter

import (
	_ "net/http/pprof"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	Namespace = "maxctrl"
)

// Exporter collects Maxscale stats from the given server and exports them
// using the prometheus metrics package
type Exporter struct {
	client *maxscale.Client
	logger log.Logger
}

// MaxscaleOpts configures options for connecting to Maxscale
type MaxscaleOpts struct {
	URI        string
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
	Timeout    time.Duration
	Insecure   bool
}

// New returns an initialized Exporter.
func New(opts MaxscaleOpts, logger log.Logger) (*Exporter, error) {
	uri := opts.URI
	if !strings.Contains(uri, "://") {
		uri = "http://" + uri
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid maxctrl URL: %s", err)
	}
	if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid maxctrl URL: %s", uri)
	}

	tlsConfig, err := maxctrl_api.SetupTLSConfig(&maxctrl_api.TLSConfig{
		Address:            opts.ServerName,
		CAFile:             opts.CAFile,
		CertFile:           opts.CertFile,
		KeyFile:            opts.KeyFile,
		InsecureSkipVerify: opts.Insecure,
	})
	if err != nil {
		return nil, err
	}
	transport := cleanhttp.DefaultPooledTransport()
	transport.TLSClientConfig = tlsConfig

	config := maxctrl_api.DefaultConfig()
	config.Address = u.Host
	config.Scheme = u.Scheme
	if config.HttpClient == nil {
		config.HttpClient = &http.Client{}
	}
	config.HttpClient.Timeout = opts.Timeout
	config.HttpClient.Transport = transport

	client, err := consul_api.NewClient(config)
	if err != nil {
		return nil, err
	}

	// Init our exporter.
	return &Exporter{
		client: client,
		logger: logger,
	}, nil
}

// Describe describes all the metrics ever exported by the maxctrl exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- up
}

// Collect fetches the stats from configured maxctrl location and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	ok := e.collectPeersMetric(ch)

	if ok {
		ch <- prometheus.MustNewConstMetric(
			up, prometheus.GaugeValue, 1.0,
		)
	} else {
		ch <- prometheus.MustNewConstMetric(
			up, prometheus.GaugeValue, 0.0,
		)
	}
}

func (e *Exporter) collectPeersMetric(ch chan<- prometheus.Metric) bool {
	peers, err := e.client.Status().Peers()
	if err != nil {
		level.Error(e.logger).Log("msg", "Can't query maxctrl", "err", err)
		return false
	}
	ch <- prometheus.MustNewConstMetric(
		clusterServers, prometheus.GaugeValue, float64(len(peers)),
	)
	return true
}

/*
// Metric for Prometheus consists of value desciption and type
type Metric struct {
	Desc      *prometheus.Desc
	ValueType prometheus.ValueType
}

var (
	serverLabelNames         = []string{"server", "address"}
	serverUpLabelNames       = []string{"server", "address", "status"}
	serviceLabelNames        = []string{"name", "router"}
	maxscaleStatusLabelNames = []string{}
	statusLabelNames         = []string{"id"}
)

type metrics map[string]Metric

func newDesc(subsystem string, name string, help string, variableLabels []string, t prometheus.ValueType) Metric {
	return Metric{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, name),
			help, variableLabels, nil),
		ValueType: t,
	}
}

// Exported MaxScale metrics for Prometheus
var (
	ServerMetrics = metrics{
		"server_connections": newDesc("server", "connections", "Amount of connections to the server", serverLabelNames, prometheus.GaugeValue),
		"server_up":          newDesc("server", "up", "Is the server up", serverUpLabelNames, prometheus.GaugeValue),
	}
	ServiceMetrics = metrics{
		"service_current_sessions": newDesc("service", "current_sessions", "Amount of sessions currently active", serviceLabelNames, prometheus.GaugeValue),
		"service_sessions_total":   newDesc("service", "total_sessions", "Total amount of sessions", serviceLabelNames, prometheus.CounterValue),
	}

	MaxscaleStatusMetrics = metrics{
		"status_uptime":  newDesc("status", "uptime", "How long has the server been running", maxscaleStatusLabelNames, prometheus.GaugeValue),
		"status_threads": newDesc("status", "threads", "Number of worker threads", maxscaleStatusLabelNames, prometheus.GaugeValue),
	}

	StatusMetrics = metrics{
		"status_read_events":                      newDesc("status", "read_events", "How many read events happened", statusLabelNames, prometheus.CounterValue),
		"status_write_events":                     newDesc("status", "write_events", "How many write events happened", statusLabelNames, prometheus.CounterValue),
		"status_error_events":                     newDesc("status", "error_events", "How many error events happened", statusLabelNames, prometheus.CounterValue),
		"status_hangup_events":                    newDesc("status", "hangup_events", "How many hangup events happened", statusLabelNames, prometheus.CounterValue),
		"status_accept_events":                    newDesc("status", "accept_events", "How many accept events happened", statusLabelNames, prometheus.CounterValue),
		"status_avg_event_queue_length":           newDesc("status", "avg_event_queue_length", "The average length of the event queue", statusLabelNames, prometheus.GaugeValue),
		"status_max_event_queue_length":           newDesc("status", "max_event_queue_length", "The maximum length of the event queue", statusLabelNames, prometheus.GaugeValue),
		"status_max_event_exec_time":              newDesc("status", "max_event_exec_time", "The maximum event execution time", statusLabelNames, prometheus.GaugeValue),
		"status_max_event_queue_time":             newDesc("status", "max_event_queue_time", "The maximum event queue time", statusLabelNames, prometheus.GaugeValue),
		"status_current_descriptors":              newDesc("status", "current_descriptors", "How many current descriptors there are", statusLabelNames, prometheus.GaugeValue),
		"status_total_descriptors":                newDesc("status", "total_descriptors", "How many total descriptors there are", statusLabelNames, prometheus.CounterValue),
		"status_load_last_second":                 newDesc("status", "load_last_second", "The load during the last measured second", statusLabelNames, prometheus.GaugeValue),
		"status_load_last_minute":                 newDesc("status", "load_last_minute", "The load during the last measured minute", statusLabelNames, prometheus.GaugeValue),
		"status_load_last_hour":                   newDesc("status", "load_last_hour", "The load during the last measured hour", statusLabelNames, prometheus.GaugeValue),
		"status_query_classifier_cache_size":      newDesc("status", "query_classifier_cache_size", "The query classifier cache size", statusLabelNames, prometheus.GaugeValue),
		"status_query_classifier_cache_inserts":   newDesc("status", "query_classifier_cache_inserts", "The number of inserts into the query classifier cache", statusLabelNames, prometheus.GaugeValue),
		"status_query_classifier_cache_hits":      newDesc("status", "query_classifier_cache_hits", "The number of hits in the query classifier cache", statusLabelNames, prometheus.GaugeValue),
		"status_query_classifier_cache_misses":    newDesc("status", "query_classifier_cache_misses", "The number of misses in the query classifier cache", statusLabelNames, prometheus.GaugeValue),
		"status_query_classifier_cache_evictions": newDesc("status", "query_classifier_cache_evictions", "The number of evictions in the query classifier cache", statusLabelNames, prometheus.GaugeValue),
	}
)
*/
