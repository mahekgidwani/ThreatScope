"""Adapters that collect security events and send them to the ThreatScope API.

Rule: an adapter never touches the database. It builds an event, calls
`ThreatScopeClient.submit_event`, and the API does validation, indicator extraction,
risk scoring and storage.
"""
