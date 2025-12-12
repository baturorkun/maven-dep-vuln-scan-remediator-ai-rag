# Version Scanner ODC

A containerized version scanner powered by OWASP Dependency-Check for analyzing project dependencies and identifying vulnerabilities.

## Prerequisites

- Docker or Podman installed
- Bash shell
- Internet connection (for initial setup)

## Quick Start

### 1. Initialize OWASP Dependency-Check Data

Before building the container, you need to download and initialize the OWASP Dependency-Check vulnerability database:

```bash
./get-odc-data.sh
```

This script will create the `odc-data` directory and download the latest vulnerability database. This step is required only once (or when you want to update the database).

### 2. Build the Container

Build the container for your platform:

**For macOS (ARM64):**
```bash
./build.sh osx
```

**For Linux (AMD64):**
```bash
./build.sh linux
```

You can also use Podman instead of Docker by setting the `CONTAINER_CLI` environment variable:
```bash
CONTAINER_CLI=podman ./build.sh osx
```

**Note:** The `--aggregate` option is incompatible with `--remediation` and `--transitive`. Do not combine `--aggregate` with those flags.

### 3. Run the Scanner

Run the version scanner container:

**For macOS:**
```bash
docker run --rm -v $(pwd):/app version-scanner:odc-arm64 --help
```

**For Linux:**
```bash
docker run --rm -v $(pwd):/app version-scanner:odc-amd64 --help
```

**With Podman:**
```bash
podman run --rm -v $(pwd):/app:Z version-scanner:odc-arm64 --help
```

### 4. Get Help

To see all available options and parameters:

```bash
docker run --rm -v $(pwd):/app version-scanner:odc-arm64 --help
```

## Usage Examples

### Basic Scan

```bash
docker run --rm -v $(pwd):/app version-scanner:odc-arm64 [options]
```

## Push to Docker Hub (Optional)

If you want to share your built image on Docker Hub:

```bash
./push.sh <your-dockerhub-username> <platform>
```

Example:
```bash
./push.sh myusername osx
```

## Directory Structure

```
version-scanner-odc/
├── README.md
├── get-odc-data.sh       # Initialize ODC data
├── build.sh              # Build container image
├── push.sh               # Push image to Docker Hub
├── Dockerfile-odc        # Container definition
├── version-scanner-odc.py # Main scanner script
└── odc-data/             # ODC vulnerability database (created by get-odc-data.sh)
```

## Troubleshooting

### "odc-data directory not found" Error

If you see this error when running `build.sh`, make sure you've run the initialization script first:
```bash
./get-odc-data.sh
```

### Permission Issues with Podman

If you encounter permission issues with Podman, add the `:Z` flag to volume mounts:
```bash
podman run --rm -v $(pwd):/app:Z version-scanner:odc-arm64 --help
```

### Updating Vulnerability Database

To update the vulnerability database, simply re-run:
```bash
./get-odc-data.sh
```

## Additional Information

For detailed information about available parameters and options, always refer to the help command:
```bash
docker run --rm -v $(pwd):/app version-scanner:odc-arm64 --help
```

## License

See the main project LICENSE file for details.
