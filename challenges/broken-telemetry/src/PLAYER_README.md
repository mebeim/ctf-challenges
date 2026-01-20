Note: you won't see stderr output from satellite, only stdout.

Build with:

    docker build -t broken-telemetry .

Run with:

    cat YOUR_INPUT | docker run --rm -i broken-telemetry
