# Git
The Git configuration manager outlines a policy management system where an agent fetches policies from a Git repository.

### Config
The following sample of a git configuration
```yaml
orb:
  labels:
    region: EU
    pop: ams02
  config_manager:
    active: git
    backends:
      git:
        url: "https://github.com/myorg/policyrepo"
        schedule: "* * * * *"
        branch: develop
        auth: "basic"
        username: "username"
        password: <password/token>
        private_key: path/to/certificate.pem
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

## Git Repository structure
Agent requires that the git repository that contains its policies to have the following:
 - a `selector.yaml` in the git root folder
 - policy files that defines 

- Agent runs lookup recursively in the git repo.
- Agent looks for a `selector.yaml` file in a directory, if it exists and metadata matches. It applies every policy that exists in the same level as  `selector.yaml`

```
.
├── .git
├── seletor.yaml
├── dir2
│   ├── newpolicy.yaml
|   └── dir3
│        └── newpolicy2.yaml
└── folder1
    └── policy1.yaml
```

### selector.yaml 
The selector.yaml must contain the `selector` section that should match the agent labels and the `policies` section that determines the policies path and if that policy is enabled or disabled. If not specified the default state is enabled.
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
      path: folder3/policy3.yaml 
```