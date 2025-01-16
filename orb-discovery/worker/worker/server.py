#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""Orb Worker Server."""


from contextlib import asynccontextmanager
from datetime import datetime

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import ValidationError

from worker.models import PolicyRequest
from worker.policy.manager import PolicyManager
from worker.version import version_semver

manager = PolicyManager()
start_time = datetime.now()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Context manager for the lifespan of the server.

    Args:
    ----
        app (FastAPI): The FastAPI app.

    """
    # Startup
    yield
    # Clean up
    manager.stop()


app = FastAPI(lifespan=lifespan)


async def parse_yaml_body(request: Request) -> PolicyRequest:
    """
    Parse the YAML body of the request.

    Args:
    ----
        request (Request): The request object.

    Returns:
    -------
        PolicyRequest: The policy request object.

    """
    if request.headers.get("content-type") != "application/x-yaml":
        raise HTTPException(
            status_code=400,
            detail="invalid Content-Type. Only 'application/x-yaml' is supported",
        )
    body = await request.body()
    try:
        return manager.parse_policy(body)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail="Invalid YAML format") from e
    except ValidationError as e:
        errors = []
        for error in e.errors():
            field_path = ".".join(str(part) for part in error["loc"])
            message = error["msg"]
            errors.append(
                {"field": field_path, "type": error["type"], "error": message}
            )
        raise HTTPException(status_code=403, detail=errors) from e
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.get("/api/v1/status")
def read_status():
    """
    Get the status of the server.

    Returns
    -------
        dict: The status of the server.

    """
    time_diff = datetime.now() - start_time
    return {
        "version": version_semver(),
        "up_time_seconds": round(time_diff.total_seconds()),
    }


@app.get("/api/v1/capabilities")
def read_capabilities():
    """
    Get the loaded modules.

    Returns
    -------
        dict: The loaded modules.

    """
    return {"loaded_modules": manager.get_loaded_modules()}


@app.post("/api/v1/policies", status_code=201)
async def write_policy(request: PolicyRequest = Depends(parse_yaml_body)):
    """
    Write a policy to the server.

    Args:
    ----
        request (PolicyRequest): The policy request object.

    Returns:
    -------
        dict: The result of the policy write.

    """
    started_policies = []
    policies = request.policies
    for name, policy in policies.items():
        try:
            manager.start_policy(name, policy)
            started_policies.append(name)
        except ValueError as e:
            raise HTTPException(status_code=409, detail=str(e))
        except Exception as e:
            for policy_name in started_policies:
                manager.delete_policy(policy_name)
            raise HTTPException(status_code=400, detail=str(e)) from e

    if not started_policies:
        raise HTTPException(status_code=400, detail="no policies found in request")

    if len(started_policies) == 1:
        return {"detail": f"policy '{started_policies[0]}' was started"}
    return {"detail": f"policies {started_policies} were started"}


@app.delete("/api/v1/policies/{policy_name}", status_code=200)
def delete_policy(policy_name: str):
    """
    Delete a policy by name.

    Args:
    ----
        policy_name (str): The name of the policy to delete.

    Returns:
    -------
        dict: The result of the deletion

    """
    try:
        manager.delete_policy(policy_name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"detail": f"policy '{policy_name}' was deleted"}
