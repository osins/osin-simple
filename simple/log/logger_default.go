package log

import "fmt"

type LoggerDefault struct {
}

func (s *LoggerDefault) Info(format string, a ...interface{}) {
	fmt.Printf("info: %s\n", fmt.Sprintf(format, a...))
}

func (s *LoggerDefault) Debug(format string, a ...interface{}) {
	fmt.Printf("debug: %s\n", fmt.Sprintf(format, a...))
}

func (s *LoggerDefault) Faild(format string, a ...interface{}) {
	fmt.Printf("info: %s\n", fmt.Sprintf(format, a...))
}

func (s *LoggerDefault) Error(format string, a ...interface{}) {
	fmt.Printf("error: %s\n", fmt.Sprintf(format, a...))
}
