package trace

import "errors"

// errNoExec marks an exec refusal (disabled or unavailable). Hops detect it to
// degrade to SKIP rather than FAIL.
var errNoExec = errors.New("exec disabled (--no-exec or exec client unavailable)")

// IsNoExec reports whether the given error is the exec-disabled sentinel.
func IsNoExec(err error) bool { return errors.Is(err, errNoExec) }
