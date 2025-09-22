# OpenTelemetry Infinity
The `opentelemetry_infinity` backend embeds the [OpenTelemetry Infinity](https://github.com/netboxlabs/opentelemetry-infinity) process inside Orb Agent to run manageable and policy-driven [otel-collector-contrib](https://github.com/open-telemetry/opentelemetry-collector-contrib) instances. Each Orb policy will spin up a new `otelcol-contrib` process running the configuration provided by the policy.

## Configuration
The `opentelemetry_infinity` backend does not require any special configuration, though overriding `host` and `port` values can be specified. Other backends will use the `otlp` settings specified in the `common` subsection to forward telemetry data if specified.


```yaml
orb:
  backends:
    opentelemetry_infinity:
      host: 192.168.5.11 # default localhost
      port: 9000 # default 10222 
    common:
      otlp:
        grpc: http://0.0.0.0:4319
        http: http://0.0.0.0:4320
```


## Policies
Policies for the `opentelemetry_infinity` backend are defined under `orb.policies.opentelemetry_infinity` in Orb agent configuration files. Each entry key under `orb.policies.opentelemetry_infinity` defines a policy that will define an OpenTelemetry Collector configuration that will be passed to the `otelcol-contrib` process. The policy body must be a valid `otelcol` configuration, as described in the [OpenTelemetry documentation](https://opentelemetry.io/docs/collector/configuration/).

### Default Collector Policy

We recommend creating a `default_collector_config` policy to provide a data pipeline to receive OTLP metrics from other backends and export them to your data repository of choice. The `otlp` endpoints defined in the `receivers` section should correspond with those defined in the `orb.backends.common.otlp` section.

Here is an example `default_collector_config` policy to write to a Grafana Cloud Prometheus database:

```yaml
orb:
  policies:
    opentelemetry_infinity:
      default_collector_config:
        extensions:
          basicauth:
            client_auth:
              username: ${env:GRAFANA_USERNAME}
              password: ${env:GRAFANA_API_TOKEN}
        receivers:
          otlp:
            protocols:
              grpc: 
                endpoint: 0.0.0.0:4319
              http: 
                endpoint: 0.0.0.0:4320
        processors:
          batch:
            send_batch_size: 1000
            send_batch_max_size: 2000
        exporters:
          prometheusremotewrite:
            endpoint: ${env:GRAFANA_TARGET}
            auth:
              authenticator: basicauth
        service:
          extensions:
            - basicauth
          pipelines:
            metrics:
              receivers: [otlp]
              processors: [batch]
              exporters: [prometheusremotewrite]
```

[!TIP]
You can reference environment variables that were passed to Orb agent on startup in your policies by using the `${env:ENV_VARIABLE_NAME}` format.

### Collector Policies
The `opentelemetry_infinity` backend packages a complete [OpenTelemetry Collector Contrib](https://github.com/open-telemetry/opentelemetry-collector-contrib) release and enables all the available Receivers, Processors,  Exporters and Connectors in that release. Collector policies simply need to be valid Collector configurations.

Here is an example policy using the `httpcheck` Receiver and exporting to our `default_collector_config` OTLP endpoint:

```yaml
orb:
  policies:
    opentelemetry_infinity:
      httpcheck_example:
        receivers:
          httpcheck:
            collection_interval: 60s
            targets:
              - endpoint: "https://netboxlabs.com"
        processors:
          batch:
            send_batch_max_size: 1000
            send_batch_size: 100
            timeout: 10s
        exporters:
          otlp:
            endpoint: http://0.0.0.0:4319
            tls:
              insecure: true
        service:
          pipelines:
            metrics:
              receivers: [httpcheck]
              processors: [batch]
              exporters: [otlp]
```

## Additional resources
- [OpenTelemetry Collector documentation](https://opentelemetry.io/docs/collector/) — complete Collector configuration documentation and examples.
- [OpenTelemetry Collector Contrib project home](https://github.com/open-telemetry/opentelemetry-collector-contrib) — release status and inventory of available Receivers, Processors, Exporters and Connectors.
- [OpenTelemetry Infinity project home](https://github.com/netboxlabs/opentelemetry-infinity) — feature overview and deployment notes.
