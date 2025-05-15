# nginx-limit-body-rate-module

nginx filter module for rate limiting HTTP request body data, ensuring controlled data flow per single connection.

See [thesis](docs/thesis.pdf) for more details on the design, implementation, and testing suite.

See my custom [request frequency limiting module](https://github.com/simonkry/nginx-limit-request-frequency-module).

## Building the nginx binary

To build the binary, please download the official open-source nginx stable version 1.26.3 source code:

`wget https://nginx.org/download/nginx-1.26.3.tar.gz`

Extract the source code:

`tar -xvf nginx-1.26.3.tar.gz`

Then, please change directory to the extracted `nginx-1.26.3`:

`cd nginx-1.26.3`

Run the `./configure` script with following parameters to statically link the external rate limiting module:

`./configure --add-module=../src`

*You can add the `--with-debug` argument to enable extended debug logging to the error log file. This allows monitoring the behavior of the implementation. However, it adds extra resource overhead and is not suitable for performance testing.*

Next, compile the source code:

`sudo make`

This creates the binary `nginx` in the `nginx-1.26.3/objs` directory.


## Testing scenarios

Several testing scenarios are designed in the [tests](./tests) directory.

Each test's results can be reproduced by running a *bash* script:

`./run_test.sh`

This script generates a temporary file of specific size in the [tmp_file](./docker/tmp_file) directory for both upload and download testing purposes.

Next, the script automatically composes a docker testing infrastructure with configured number of clients (=20), each simulating HTTP/1.1 traffic.

The tests run up to several minutes. Results are saved in `.csv` format in the `results` subdirectory.


## Docker testing infrastructure

**Note:** The environment was built using *Docker version 28.1.1, build 4eba377*.

First, change directory to one of the testing scenarios. Each test creates its own docker environment.

To build the images (based on `alpine` and `debian:stable-slim`), run:

`docker compose build`

You can edit the file `.env` to customize testing scenarios.

Next, run the containers in the background with N clients:

`docker compose up -d --scale client=N`

This creates a network access point (PoP) simulation with an nginx reverse proxy server and one backend Apache web server. Clients automatically run an HTTP/1.1 [traffic testing script](./docker/client/client_traffic_test.sh) over public network simulation.

Inspect the nginx reverse proxy server (for logs) or simulate your own client traffic:

`docker compose exec reverse-proxy bash` and `docker compose exec client sh`

To stop and remove running containers along with associated networks, use the following command:

`docker compose down`