package core

import (
	"go.uber.org/zap"

	"context"
)

func getLoggerFromContext(ctx context.Context) *zap.Logger {
	if v := ctx.Value("logger"); v != nil {
		if logger, ok := v.(*zap.Logger); ok {
			return logger
		}
	}

	return zap.L()
}
