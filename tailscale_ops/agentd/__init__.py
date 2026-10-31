"""tn-agent: the approval service on a region's control host.

An Agent asks for a change over MCP; the change waits until the owner approves it on a page the
service serves, with a passkey. Only then does the service run it, with the headscale CLI on this
host. The package runs on the control host from one zip (python3 agentd.pyz) and imports nothing
outside the standard library and itself, so it keeps to Python 3.8.
"""

VERSION = "1"
