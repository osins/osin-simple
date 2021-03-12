package log

type Logger interface {
	Error(format string, a ...interface{})
	Info(format string, a ...interface{})
	Debug(format string, a ...interface{})
	Faild(format string, a ...interface{})
}
