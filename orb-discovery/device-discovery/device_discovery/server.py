#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Device Discovery Server."""


import time
from contextlib import asynccontextmanager
from datetime import datetime

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import ValidationError

from device_discovery.discovery import supported_drivers
from device_discovery.metrics import get_metric
from device_discovery.policy.manager import PolicyManager
from device_discovery.policy.models import PolicyRequest
from device_discovery.version import version_semver

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


# Add middleware to track API requests and latency
@app.middleware("http")
async def add_metrics(request: Request, call_next):
    """
    Add middleware to track API requests and latency.

    Args:
    ----
        request (Request): The request object.
        call_next: The next middleware or route handler.

    Returns:
    -------
        response: The response object.

    """
    api_requests = get_metric("api_requests")
    api_response_latency = get_metric("api_response_latency")
    if api_requests is None or api_response_latency is None:
        return await call_next(request)
    api_requests.add(1, {"path": request.url.path, "method": request.method})

    start_time = time.perf_counter()
    response = await call_next(request)
    duration = (time.perf_counter() - start_time) * 1000

    api_response_latency.record(
        duration,
        {
            "path": request.url.path,
            "method": request.method,
            "status_code": response.status_code,
        },
    )

    return response


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
    Get the supported drivers.

    Returns
    -------
        dict: The supported drivers.

    """
    return {"supported_drivers": supported_drivers}


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
