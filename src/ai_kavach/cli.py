import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="AI Kavach Cyber Reasoning System")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the pipeline on a target")
    run_parser.add_argument("--target", type=Path, required=True, help="Path to the target codebase")
    run_parser.add_argument("--time-budget", type=int, required=True, help="Time budget in seconds")
    run_parser.add_argument("--run-id", type=str, default="default_run", help="Run identifier")

    args = parser.parse_args()

    # Load configuration to fail fast if ANTHROPIC_API_KEY is missing
    from ai_kavach.config import get_config
    try:
        config = get_config()
    except RuntimeError as e:
        print(f"Startup Error: {e}", file=sys.stderr)
        return 1

    if args.command == "run":
        print(f"Starting AI Kavach pipeline for target: {args.target}")
        print(f"Time budget: {args.time_budget} seconds, Run ID: {args.run_id}")
        
        # Pipeline stages will be wired here as they are built
        print("Pipeline stages not yet implemented.")
        raise NotImplementedError("Pipeline stages are not yet built.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
