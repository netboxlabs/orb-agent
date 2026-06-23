## Nbl Custom Worker
A simple implementation for testing. It shows how to define your own data structures to parse `config` and `scope` data. Also returns a `Device` entity to be ingested.


## Policy samples

### Sample list scope
``` yaml
policies:
    custom_1:
        config:
          package: nbl_custom
          custom: any_value
        scope:
          - hostname: 10.90.0.50
            password: *****
            username: admin
```

### Sample map scope
``` yaml
policies:
    custom_1:
        config:
          package: nbl_custom
          custom: any_value
        scope:
           target: 10.90.0.50
           port: 8080
```