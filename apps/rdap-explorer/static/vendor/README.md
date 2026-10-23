# Vendored client libraries

Committed to git so the build stays pure-cargo (no npm/node required).

| File | Package | Version | Source |
|---|---|---|---|
| htmx.min.js | htmx.org | 2.0.11 | https://unpkg.com/htmx.org@2.0.11/dist/htmx.min.js |
| alpine.min.js | alpinejs | 3.17.4 | https://cdn.jsdelivr.net/npm/alpinejs@3.17.4/dist/cdn.min.js |

## Updating a library

    curl -sL -o htmx.min.js "https://unpkg.com/htmx.org@<version>/dist/htmx.min.js"
    curl -sL -o alpine.min.js "https://cdn.jsdelivr.net/npm/alpinejs@<version>/dist/cdn.min.js"

Then bump the version table above and commit.
