# MaxScale Exporter

The Exporter exports the MaxScale metrics for Prometheus:

- Server connections
- Service session count
- MaxScale instance status
- Event statistics per started thread

## MaxScale requirements

The exporter uses exclusively [MaxScale REST API](https://mariadb.com/kb/en/maxscale-23-rest-api/)

## Installation

1. Install [Golang](https://golang.org/doc/install)
1. Create a new folder in your $GOPATH: `mkdir -p $GOPATH/src/github.com/`
1. Navigate to that folder: `$GOPATH/src/github.com`
1. Clone the repository: `git clone https://github.com/pgporada/maxctrl_exporter.git`

## Build

### Manually

1. Change to the project root directory
1. Run `go build` to build the binary for your platform
1. Build Linux binary: `GOOS=linux GOARCH=amd64 go build -o bin/linux/maxctrl_exporter`
