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

package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-kit/kit/log/level"
	"github.com/pgporada/maxscale_exporter/pkg/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/alecthomas/kingpin.v2"
)

/*
// MaxScale contains connection parameters to the server and metric maps
type MaxScale struct {
	address               string
	username              string
	password              string
	up                    prometheus.Gauge
	totalScrapes          prometheus.Counter
	serverMetrics         map[string]Metric
	serviceMetrics        map[string]Metric
	maxscaleStatusMetrics map[string]Metric
	statusMetrics         map[string]Metric
}
*/

type promHTTPLogger struct {
	logger log.logger
}

func (l promHTTPLogger) Println(v ...interface{}) {
	level.Error(l.logger).Log("msg", fmt.Sprint(v...))
}

func init() {
	prometheus.MustRegister(version.NewCollector("maxscale_exporter"))
}

func main() {
	var (
		webConfig     = webflag.AddFlags(kingpin.CommandLine)
		listenAddress = kingpin.Flag("web.listen-address", "Address to listen on for telemetry.").Default("0.0.0.0:8080").String()
		metricsPath   = kingpin.Flag("web.metrics-path", "Path which to expose metrics.").Default("/metrics").String()
	)
	kingpin.Flag("maxctrl.server", "REST API address for Maxscale. (prefix with https:// to connect over HTTPS)").Default("http://127.0.0.1:8989").StringVar(&opts.URI)
	kingpin.Flag("maxctrl.ca-file", "File path to a PEM-encoded certificate authority used to validate the authenticity of a server certificate.").Default("").StringVar(&opts.CAFile)
	kingpin.Flag("maxctrl.cert-file", "File path to a PEM-encoded certificate used with the private key to verify the exporter's authenticity.").Default("").StringVar(&opts.CertFile)
	kingpin.Flag("maxctrl.key-file", "File path to a PEM-encoded private key used with the certificate to verify the exporter's authenticity.").Default("").StringVar(&opts.KeyFile)
	kingpin.Flag("maxctrl.server-name", "When provided, this overrides the hostname for the TLS certificate. It can be used to ensure that the certificate name matches the hostname we declare.").Default("").StringVar(&opts.ServerName)
	kingpin.Flag("maxctrl.timeout", "Timeout on HTTP requests to the Maxscale REST API.").Default("1000ms").DurationVar(&opts.Timeout)
	kingpin.Flag("maxctrl.insecure", "Disable TLS host verification.").Default("false").BoolVar(&opts.Insecure)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting maxctrl_exporter", "version", version.Info())
	level.Info(logger).Log("build_context", version.BuildContext())

	exporter, err := exporter.New(opts, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating the exporter", "err", err)
		os.Exit(1)
	}

	http.Handle(*metricsPath,
		promhttp.InstrumentMetricHandler(
			prometheus.DefaultRegisterer,
			promhttp.HandlerFor(
				prometheus.DefaultGatherer,
				promhttp.HandlerOpts{
					ErrorLog: &promHTTPLogger{
						logger: logger,
					},
				},
			),
		),
	)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Maxscale Exporter</title></head>
             <body>
             <h1>Maxscale Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             <h2>Options</h2>
             </dl>
             <h2>Build</h2>
             <pre>` + version.Info() + ` ` + version.BuildContext() + `</pre>
             </body>
             </html>`))
	})
	http.HandleFunc("/-/healthy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})
	http.HandleFunc("/-/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)
	srv := &http.Server{Addr: *listenAddress}
	if err := web.ListenAndServe(srv, *webConfig, logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}

}

/*
// NewExporter creates a new instance of the MaxScale
func NewExporter(address string, username string, password string) (*MaxScale, error) {
	return &MaxScale{
		address:  address,
		username: username,
		password: password,
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "up",
			Help:      "Was the last scrape of MaxScale successful?",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "exporter_total_scrapes",
			Help:      "Current total MaxScale scrapes",
		}),
		serverMetrics:         ServerMetrics,
		serviceMetrics:        ServiceMetrics,
		maxscaleStatusMetrics: MaxscaleStatusMetrics,
		statusMetrics:         StatusMetrics,
	}, nil
}

// Describe describes all the metrics ever exported by the MaxScale exporter. It
// implements prometheus.Collector.
func (m *MaxScale) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range m.serverMetrics {
		ch <- m.Desc
	}

	for _, m := range m.serviceMetrics {
		ch <- m.Desc
	}

	for _, m := range m.maxscaleStatusMetrics {
		ch <- m.Desc
	}

	for _, m := range m.statusMetrics {
		ch <- m.Desc
	}

	ch <- m.up.Desc()
	ch <- m.totalScrapes.Desc()
}

// Collect fetches the stats from configured MaxScale location and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (m *MaxScale) Collect(ch chan<- prometheus.Metric) {
	m.totalScrapes.Inc()

	var parseErrors = false

	if err := m.parseServers(ch); err != nil {
		parseErrors = true
		log.Print(err)
	}

	if err := m.parseServices(ch); err != nil {
		parseErrors = true
		log.Print(err)
	}

	if err := m.parseMaxscaleStatus(ch); err != nil {
		parseErrors = true
		log.Print(err)
	}

	if err := m.parseThreadStatus(ch); err != nil {
		parseErrors = true
		log.Print(err)
	}

	if parseErrors {
		m.up.Set(0)
	} else {
		m.up.Set(1)
	}

	ch <- m.up
	ch <- m.totalScrapes
}

func (m *MaxScale) getStatistics(path string, v interface{}) error {
	var err error
	req, err := http.NewRequest("GET", "http://"+m.address+"/v1"+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(m.username, m.password)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error while getting %v: %v", path, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err = fmt.Errorf("the MaxScale statistic request failed with a status: %s", resp.Status)
		return err
	}

	return json.NewDecoder(resp.Body).Decode(v)
}

func serverUp(status string) int {
	if strings.Contains(status, ",Down,") {
		return 0
	}
	if strings.Contains(status, ",Running,") {
		return 1
	}
	return 0
}

func (m *MaxScale) createMetricForPrometheus(metricsMap map[string]Metric, metricKey string,
	value int, ch chan<- prometheus.Metric, labelValues ...string) {

	metric := metricsMap[metricKey]
	ch <- prometheus.MustNewConstMetric(
		metric.Desc,
		metric.ValueType,
		float64(value),
		labelValues...,
	)
}

func (m *MaxScale) parseServers(ch chan<- prometheus.Metric) error {
	var servers Servers
	err := m.getStatistics("/servers", &servers)

	if err != nil {
		return err
	}

	for _, server := range servers.Data {
		serverID := server.ID
		serverAddress := server.Attributes.Parameters.Address
		m.createMetricForPrometheus(m.serverMetrics, "server_connections",
			server.Attributes.Statistics.Connections, ch, serverID, serverAddress)

		// We surround the separated list with the separator as well. This way regular expressions
		// in labeling don't have to consider satus positions.
		normalizedStatus := "," + strings.Replace(server.Attributes.State, ", ", ",", -1) + ","
		m.createMetricForPrometheus(m.serverMetrics, "server_up",
			serverUp(normalizedStatus), ch, serverID, serverAddress, normalizedStatus)
	}

	return nil
}

func (m *MaxScale) parseServices(ch chan<- prometheus.Metric) error {
	var services Services
	err := m.getStatistics("/services", &services)

	if err != nil {
		return err
	}

	for _, service := range services.Data {
		m.createMetricForPrometheus(m.serviceMetrics, "service_current_sessions",
			service.Attributes.Connections, ch, service.ID, service.Attributes.Router)

		m.createMetricForPrometheus(m.serviceMetrics, "service_sessions_total",
			service.Attributes.Connections, ch, service.ID, service.Attributes.Router)
	}

	return nil
}

func (m *MaxScale) parseMaxscaleStatus(ch chan<- prometheus.Metric) error {
	var maxscaleStatus MaxscaleStatus
	err := m.getStatistics("/maxscale", &maxscaleStatus)

	if err != nil {
		return err
	}

	m.createMetricForPrometheus(m.maxscaleStatusMetrics, "status_uptime",
		maxscaleStatus.Data.Attributes.Uptime, ch)

	m.createMetricForPrometheus(m.maxscaleStatusMetrics, "status_threads",
		maxscaleStatus.Data.Attributes.Parameters.Threads, ch)

	return nil
}
func (m *MaxScale) parseThreadStatus(ch chan<- prometheus.Metric) error {
	var threadStatus ThreadStatus
	err := m.getStatistics("/maxscale/threads", &threadStatus)

	if err != nil {
		return err
	}

	for _, threadStatus := range threadStatus.Data {
		m.createMetricForPrometheus(m.statusMetrics, "status_read_events",
			threadStatus.Attributes.Stats.Reads, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_write_events",
			threadStatus.Attributes.Stats.Writes, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_error_events",
			threadStatus.Attributes.Stats.Errors, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_hangup_events",
			threadStatus.Attributes.Stats.Hangups, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_accept_events",
			threadStatus.Attributes.Stats.Accepts, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_avg_event_queue_length",
			threadStatus.Attributes.Stats.AvgEventQueueLength, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_max_event_queue_length",
			threadStatus.Attributes.Stats.MaxEventQueueLength, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_max_event_exec_time",
			threadStatus.Attributes.Stats.MaxExecTime, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_max_event_queue_time",
			threadStatus.Attributes.Stats.MaxQueueTime, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_current_descriptors",
			threadStatus.Attributes.Stats.CurrentDescriptors, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_total_descriptors",
			threadStatus.Attributes.Stats.TotalDescriptors, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_load_last_second",
			threadStatus.Attributes.Stats.Load.LastSecond, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_load_last_minute",
			threadStatus.Attributes.Stats.Load.LastMinute, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_load_last_hour",
			threadStatus.Attributes.Stats.Load.LastHour, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_query_classifier_cache_size",
			threadStatus.Attributes.Stats.QueryClassifierCache.Size, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_query_classifier_cache_inserts",
			threadStatus.Attributes.Stats.QueryClassifierCache.Inserts, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_query_classifier_cache_hits",
			threadStatus.Attributes.Stats.QueryClassifierCache.Hits, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_query_classifier_cache_misses",
			threadStatus.Attributes.Stats.QueryClassifierCache.Misses, ch, threadStatus.ID)
		m.createMetricForPrometheus(m.statusMetrics, "status_query_classifier_cache_evictions",
			threadStatus.Attributes.Stats.QueryClassifierCache.Evictions, ch, threadStatus.ID)
	}

	return nil
}

func main() {
	maxScaleAddress := os.Getenv("MAXSCALE_ADDRESS")
	if len(maxScaleAddress) == 0 {
		maxScaleAddress = "127.0.0.1"
	}

	maxScalePort := os.Getenv("MAXSCALE_PORT")
	if len(maxScalePort) == 0 {
		maxScalePort = "8989"
	}

	maxScaleUsername := os.Getenv("MAXSCALE_USERNAME")
	if len(maxScaleUsername) == 0 {
		maxScaleUsername = "admin"
	}

	maxScalePassword := os.Getenv("MAXSCALE_PASSWORD")
	if len(maxScalePassword) == 0 {
		maxScalePassword = "mariadb"
	}

	maxScaleExporterPort := os.Getenv("MAXSCALE_EXPORTER_PORT")
	if len(maxScaleExporterPort) == 0 {
		maxScaleExporterPort = "8080"
	}

	maxScaleFullAddress := maxScaleAddress + ":" + maxScalePort
	log.Print("Starting MaxScale exporter")
	log.Printf("Scraping MaxScale JSON API at: %s", maxScaleFullAddress)

	exporter, err := NewExporter(maxScaleFullAddress, maxScaleUsername, maxScalePassword)
	if err != nil {
		log.Fatalf("Failed to start maxscale exporter: %v\n", err)
	}

	prometheus.MustRegister(exporter)

	http.Handle(metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
			<head><title>MaxScale Exporter</title></head>
			<body>
			<h1>MaxScale Exporter</h1>
			<p><a href="` + metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})
	log.Printf("Started MaxScale exporter, listening on port: %v", maxScaleExporterPort)
	log.Fatal(http.ListenAndServe(localIP+":"+maxScaleExporterPort, nil))
}
*/
