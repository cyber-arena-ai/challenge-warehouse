# Jenkins runtime selection

`release` selects a Jenkins distribution already present in the image. The
supported values are `2.554` and `2.555`. Run the arena `restart_service` tool
after changing it. Jenkins home, jobs, build history, and planted state are
preserved across a service restart.
