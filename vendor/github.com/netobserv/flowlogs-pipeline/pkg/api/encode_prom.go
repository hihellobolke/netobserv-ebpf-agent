/*
 * Copyright (C) 2022 IBM, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package api

type PromTLSConf struct {
	CertPath string `yaml:"certPath,omitempty" json:"certPath,omitempty" doc:"path to the certificate file"`
	KeyPath  string `yaml:"keyPath,omitempty" json:"keyPath,omitempty" doc:"path to the key file"`
}

type PromEncode struct {
	*PromConnectionInfo
	Metrics    PromMetricsItems `yaml:"metrics,omitempty" json:"metrics,omitempty" doc:"list of prometheus metric definitions, each includes:"`
	Prefix     string           `yaml:"prefix,omitempty" json:"prefix,omitempty" doc:"prefix added to each metric name"`
	ExpiryTime Duration         `yaml:"expiryTime,omitempty" json:"expiryTime,omitempty" doc:"time duration of no-flow to wait before deleting prometheus data item"`
	MaxMetrics int              `yaml:"maxMetrics,omitempty" json:"maxMetrics,omitempty" doc:"maximum number of metrics to report (default: unlimited)"`
}

type PromEncodeOperationEnum struct {
	Gauge        string `yaml:"gauge" json:"gauge" doc:"single numerical value that can arbitrarily go up and down"`
	Counter      string `yaml:"counter" json:"counter" doc:"monotonically increasing counter whose value can only increase"`
	Histogram    string `yaml:"histogram" json:"histogram" doc:"counts samples in configurable buckets"`
	AggHistogram string `yaml:"agg_histogram" json:"agg_histogram" doc:"counts samples in configurable buckets, pre-aggregated via an Aggregate stage"`
}

func PromEncodeOperationName(operation string) string {
	return GetEnumName(PromEncodeOperationEnum{}, operation)
}

type PromConnectionInfo struct {
	Address string       `yaml:"address,omitempty" json:"address,omitempty" doc:"endpoint address to expose"`
	Port    int          `yaml:"port,omitempty" json:"port,omitempty" doc:"endpoint port number to expose"`
	TLS     *PromTLSConf `yaml:"tls,omitempty" json:"tls,omitempty" doc:"TLS configuration for the endpoint"`
}

type PromMetricsItem struct {
	Name       string              `yaml:"name" json:"name" doc:"the metric name"`
	Type       string              `yaml:"type" json:"type" enum:"PromEncodeOperationEnum" doc:"one of the following:"`
	Filter     PromMetricsFilter   `yaml:"filter,omitempty" json:"filter,omitempty" doc:"an optional criterion to filter entries by. Deprecated: use filters instead."`
	Filters    []PromMetricsFilter `yaml:"filters" json:"filters" doc:"a list of criteria to filter entries by"`
	ValueKey   string              `yaml:"valueKey" json:"valueKey" doc:"entry key from which to resolve metric value"`
	Labels     []string            `yaml:"labels" json:"labels" doc:"labels to be associated with the metric"`
	Buckets    []float64           `yaml:"buckets" json:"buckets" doc:"histogram buckets"`
	ValueScale float64             `yaml:"valueScale" json:"valueScale" doc:"scale factor of the value (MetricVal := FlowVal / Scale)"`
}

func (i *PromMetricsItem) GetFilters() []PromMetricsFilter {
	if len(i.Filters) == 0 && i.Filter.Key != "" {
		return []PromMetricsFilter{i.Filter}
	}
	return i.Filters
}

type PromMetricsItems []PromMetricsItem

type PromMetricsFilter struct {
	Key   string `yaml:"key" json:"key" doc:"the key to match and filter by"`
	Value string `yaml:"value" json:"value" doc:"the value to match and filter by"`
	Type  string `yaml:"type" json:"type" enum:"PromEncodeFilterTypeEnum" doc:"the type of filter match: exact (default), presence, absence or regex"`
}

type PromEncodeFilterTypeEnum struct {
	Exact    string `yaml:"exact" json:"exact" doc:"match exactly the provided fitler value"`
	Presence string `yaml:"presence" json:"presence" doc:"filter key must be present (filter value is ignored)"`
	Absence  string `yaml:"absence" json:"absence" doc:"filter key must be absent (filter value is ignored)"`
	Regex    string `yaml:"regex" json:"regex" doc:"match filter value as a regular expression"`
}

func PromEncodeFilterTypeName(t string) string {
	return GetEnumName(PromEncodeFilterTypeEnum{}, t)
}
