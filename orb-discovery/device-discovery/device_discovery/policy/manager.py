#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""Orb Discovery Policy Manager."""

import logging

import yaml

from device_discovery.parser import resolve_env_vars
from device_discovery.policy.models import Policy, PolicyRequest
from device_discovery.policy.runner import PolicyRunner

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PolicyManager:
    """Policy Manager class."""

    def __init__(self):
        """Initialize the PolicyManager instance with an empty list of policies."""
        self.runners = dict[str, PolicyRunner]()

    def start_policy(self, name: str, policy: Policy):
        """
        Start the policy for the given configuration.

        Args:
        ----
            name: Policy name
            policy: Policy configuration

        """
        if self.policy_exists(name):
            raise ValueError(f"policy '{name}' already exists")

        runner = PolicyRunner()
        runner.setup(name, policy.config, policy.scope)
        self.runners[name] = runner

    def parse_policy(self, config_data: bytes) -> PolicyRequest:
        """
        Parse the YAML configuration data into a Policy object.

        Args:
        ----
            config_data (str): The YAML configuration data as a string.

        Returns:
        -------
            Config: The configuration object.

        """
        config = yaml.safe_load(config_data)
        config = resolve_env_vars(config)
        return PolicyRequest(**config)

    def policy_exists(self, name: str) -> bool:
        """
        Check if the policy exists.

        Args:
        ----
            name: Policy name

        Returns:
        -------
            bool: True if the policy exists, False otherwise

        """
        return name in self.runners

    def delete_policy(self, name: str):
        """
        Delete the policy by name.

        Args:
        ----
            name: Policy name.

        """
        if not self.policy_exists(name):
            raise ValueError(f"policy '{name}' not found")
        self.runners[name].stop()
        del self.runners[name]

    def stop(self):
        """Stop all running policies."""
        for name, runner in self.runners.items():
            logger.info(f"Stopping policy '{name}'")
            runner.stop()
        self.runners = []
