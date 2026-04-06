package proxy

type noopLogger struct{}

func (noopLogger) Debug(string, ...any) {}
func (noopLogger) Info(string, ...any)  {}
func (noopLogger) Warn(string, ...any)  {}
func (noopLogger) Error(string, ...any) {}

type noopMetrics struct{}

func (noopMetrics) IncCounter(string, map[string]string)                {}
func (noopMetrics) ObserveHistogram(string, float64, map[string]string) {}
func (noopMetrics) SetGauge(string, float64, map[string]string)         {}
