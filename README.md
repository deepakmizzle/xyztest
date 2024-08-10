
## netguard

This project utilizes Rust and eBPF to manage network traffic based on configured rules.
Prerequisites

**Install Rust Stable Toolchain:**

``` rustup install stable ```

**Install Rust Nightly Toolchain:**

```rustup install nightly```

**Install bpf-linker:**

```cargo install bpf-linker```

**Build eBPF**

To build the eBPF program, use the following command:

```cargo xtask build-ebpf```

For a release build, add the --release flag. You can also specify the target architecture with the --target flag.
Build Userspace

To build the userspace application, run:

``` cargo build ```

To run the userspace application along with the eBPF program, use:


```cargo xtask run```

**API Usage**

The NetGuard service provides an API endpoint for applying network blocking rules.
Applying Network Blocking Rules

To apply network blocking rules, send a POST request to the /start_blocknet endpoint with the JSON data defining the rules.
API Input JSON Data

Here's the structure of the JSON data you need to provide in the request body:

json
```
{
  "blocked_protocol_type": [
    "UDP"
  ],
  "blocked_ip_list": [
    "192.168.1.100",
    "10.0.0.1",
    "172.16.0.10",
    "23.55.106.40",
    "127.0.0.0",
    "157.240.239.60"
  ],
  "blocked_ports": [
    8000,
    3000,
    443
  ],
  "blocked_net_type": [
    "IPV6"
  ]
}
```
**Fields**

    blocked_protocol_type: An array of network protocol types (e.g., "UDP", "TCP") to block.
    blocked_ip_list: An array of IP addresses to block.
    blocked_ports: An array of port numbers to block.
    blocked_net_type: An array of network types (e.g., "IPV4", "IPV6") to block.

**Example Request Using curl**

```

curl -X POST http://localhost:8080/start_blocknet \
-H "Content-Type: application/json" \
-d '{
  "blocked_protocol_type": ["UDP"],
  "blocked_ip_list": [
    "192.168.1.100",
    "10.0.0.1",
    "172.16.0.10",
    "23.55.106.40",
    "127.0.0.0",
    "157.240.239.60"
  ],
  "blocked_ports": [8000, 3000, 443],
  "blocked_net_type": ["IPV6"]
}'
```
**API Responses**

    200 OK: The request was successful, and the network blocking configuration was applied.
    400 Bad Request: The request was invalid or malformed.
    500 Internal Server Error: An unexpected error occurred while processing the request.

**Successful Response Example**

**json**
```
{
  "status": "success",
  "message": "The blocknet service has been started."
}
```

**Error Response Example**

**json**

```
{
  "status": "error",
  "message": "Internal server error. Please try again later."
}
```

**Troubleshooting**

    Ensure the eBPF Program is Built: Verify that the eBPF program is compiled and located at the specified path.
    Check Logs: Review the service logs for errors or additional information about issues.

**Contributing**

Contributions are welcome! Please follow the standard fork-and-pull request workflow. Ensure that your changes are well-tested and documented.
License

**This project is licensed under the MIT License. See the LICENSE file for details.**