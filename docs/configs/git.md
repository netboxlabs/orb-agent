# Git
The Git configuration manager outlines a policy management system where an agent fetches policies from a Git repository.

**Important**: The `config_manager` and `backends` sections must still be passed directly to the agent via the config file at startup time. These components are not yet dynamically reconfigurable, so ensure the relevant settings are correctly defined before launching the agent.

### Config
The following sample of a git configuration
```yaml
orb:
  labels:
    region: EU
    pop: ams02
  config_manager:
    active: git
    sources:
      git:
        url: "https://github.com/myorg/policyrepo"
        schedule: "* * * * *"
        branch: develop
        auth: "basic"
        username: "username"
        password: ${PASSWORD|TOKEN}
        private_key: path/to/certificate.pem
  backends:
    network_discovery:
    device_discovery:
    ...
```

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| url | string | yes  |  the url of the repository  that contain agent policies  |
| schedule | cron format | no  |  If defined, it will execute fetch remote changes on cron schedule time. If not defined, it will execute the match and apply policies only once  |
| branch | string | no  |  the git branch that should be used by the agent. If not specified, the default branch will be used   |
| auth | string | no | it can be either 'basic' or 'ssh'. The basic authentication supports both password or token. If not specified, no auth will be used (public repository) |
| username | string | no | username used for authentication |
| password | string | no | the password used for authentication. If the auth method is 'basic' it should cointains the password or auth token. If the method is 'ssh' it should contains the password for the ssh certificate file |
| private_key | string | no | the path for the ssh certificate file |

## Git Repository Structure

The Orb Agent requires the Git repository containing its policies to have the following structure:
- A `selector.yaml` file in the root folder of the repository
- Policy files that define agent policies

### Sample Structure
```
.
├── .git
├── selector.yaml
├── policy1.yaml
├── folder2
│   ├── policy2.yaml
│   └── folder3
│       └── policy3.yaml
└── folder4
    └── policy4.yaml
```

### selector.yaml 
The `selector.yaml` file must include the `selector` and `policies` sections:
 - `selector`: Defines key-value pairs that identify agents based on their labels. If the selector is empty, it matches all agents.
 - `policies`: Specifies policy file paths and their enabled or disabled state. If the `enabled` field is not provided, the policy is enabled by default


```yaml
agent_selector_1:
  selector:
    region: EU
    pop: ams02
  policies:
    policy1:
      path: policy1.yaml
    policy2:
      enabled: false
      path: folder2/policy2.yaml
agent_selector_2:
  selector:
    region: US
    pop: nyc02
  policies:
    policy1:
      enabled: true
      path: policy1.yaml
    policy3:
      path: folder2/folder3/policy3.yaml
agent_selector_matches_all:
  selector:
  policies:
    path: folder4/policy4.yaml
```

### policy.yaml
Each policy file should explicitly declare the backend it applies to within the policy data itself. For example, a `policy.yaml` that targets the `device_discovery` backend might look like this:

```yaml
device_discovery:
  discovery_1:
    config:
      schedule: "* * * * *"
      defaults:
        site: New York NY
    scope:
      - driver: ios
        hostname: 192.168.0.5
        username: admin
        password: ${PASS}
```