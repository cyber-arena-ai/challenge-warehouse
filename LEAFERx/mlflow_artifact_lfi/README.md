# MLflow tracking service

This package runs the exact pinned MLflow source with native basic-auth users,
persistent SQLite state, editable source, and application-level trace workflows.

The service listens on HTTP port 5000. During a game, use
`get_attack_targets` for the native credentials and current objective locators.
