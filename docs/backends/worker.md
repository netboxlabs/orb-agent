# Worker
The worker backend TBD.


## Configuration
The `worker` backend does not require any special configuration, though overriding `host` and `port` values can be specified. The backend will use the `diode` settings specified in the `common` subsection to forward discovery results.


```yaml
orb:
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        api_key: ${DIODE_API_KEY}
        agent_name: agent01
    worker:
      host: 192.168.5.11 # default 0.0.0.0
      port: 8857 # default 8071

```

## Policy
Worker policies are broken down into two subsections: `config` and `scope`. 

### Config
Config defines data for the whole scope and is optional overall.

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| package | str | yes  |  custom python package that implements Backend Class  |
| schedule | cron format | no  |  If defined, it will execute scope following cron schedule time. If not defined, it will execute scope only once  |


### Scope
The scope can be defined


### Sample
A sample policy including all parameters supported by the device discovery backend.
```yaml
orb:
  ...
  policies:
    worker:
      custom_policy:
        config:
          package: nbl_custom
          schedule: "* * * * *"
          custom_config: custom
        scope:
          custom: any