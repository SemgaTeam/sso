package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"

	"os"
)

var Log *zap.Logger

func InitLogger(logFile string) {
	rotate := &lumberjack.Logger{
		Filename: logFile,
		MaxSize: 10,
		MaxBackups: 5,
		MaxAge: 30,
		Compress: true,
	}

	fileWriter := zapcore.AddSync(rotate)
	consoleWriter := zapcore.AddSync(os.Stdout)

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.TimeKey = "time"
	encoderCfg.LevelKey = "level"
	encoderCfg.CallerKey = "caller"
	encoderCfg.MessageKey = "message"

	consoleEncoder := zapcore.NewConsoleEncoder(encoderCfg)
	fileEncoder := zapcore.NewJSONEncoder(encoderCfg)
	logLevel := zap.InfoLevel

	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleWriter, logLevel),
		zapcore.NewCore(fileEncoder, fileWriter, logLevel),
	)

	Log = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
}
