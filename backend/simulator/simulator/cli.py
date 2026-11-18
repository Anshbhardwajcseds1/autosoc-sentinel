"""
CLI for generating simulated security events.

Usage:
    python -m simulator.cli --type phishing_email --count 3
    python -m simulator.cli --type auth_log --scenario brute_force
    python -m simulator.cli --type random --count 10
    python -m simulator.cli --list-scenarios
    python -m simulator.cli --submit --type phishing_email
"""

from __future__ import annotations

import argparse
import json
import sys

from simulator.generator import GENERATORS, generate_batch, generate_event


def list_scenarios():
    """Print all available event types and scenarios."""
    print("\nAvailable Event Types and Scenarios:")
    print("=" * 50)
    for event_type, scenarios in GENERATORS.items():
        print(f"\n  {event_type}:")
        for name, func in scenarios.items():
            doc = func.__doc__ or "No description"
            print(f"    - {name}: {doc.strip()}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="AutoSOC Sentinel - Event Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--type", "-t",
        choices=["phishing_email", "auth_log", "malware_alert", "random"],
        default="random",
        help="Event type to generate (default: random)",
    )
    parser.add_argument(
        "--scenario", "-s",
        default=None,
        help="Specific scenario (e.g. brute_force, credential_phishing)",
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=1,
        help="Number of events to generate (default: 1)",
    )
    parser.add_argument(
        "--list-scenarios", "-l",
        action="store_true",
        help="List all available scenarios",
    )
    parser.add_argument(
        "--submit",
        action="store_true",
        help="Submit generated events to the running API",
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="API base URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--pretty", "-p",
        action="store_true",
        help="Pretty-print JSON output",
    )

    args = parser.parse_args()

    if args.list_scenarios:
        list_scenarios()
        return

    event_type = None if args.type == "random" else args.type

    try:
        events = generate_batch(
            count=args.count,
            event_type=event_type,
            scenario=args.scenario,
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.submit:
        try:
            import httpx
        except ImportError:
            print("Error: httpx is required for --submit. Install with: pip install httpx", file=sys.stderr)
            sys.exit(1)

        print(f"Submitting {len(events)} event(s) to {args.api_url}...")
        for i, event in enumerate(events):
            try:
                resp = httpx.post(
                    f"{args.api_url}/api/events",
                    json={
                        "event_type": event["event_type"],
                        "raw_content": event["raw_content"],
                        "source": event["source"],
                    },
                    timeout=30.0,
                )
                resp.raise_for_status()
                result = resp.json()
                print(f"  [{i+1}/{len(events)}] Submitted: incident_id={result.get('incident_id', '?')} "
                      f"({event['scenario']}, malicious={event['is_malicious']})")
            except Exception as e:
                print(f"  [{i+1}/{len(events)}] Failed: {e}", file=sys.stderr)
    else:
        indent = 2 if args.pretty else None
        for event in events:
            print(json.dumps(event, indent=indent, default=str))


if __name__ == "__main__":
    main()
