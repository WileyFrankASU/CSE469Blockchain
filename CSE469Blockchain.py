import argparse
import os
import sys

from blockchain2 import Blockchain


def parse_arguments():
    parser = argparse.ArgumentParser(description="Blockchain Chain of Custody")

    # Define subcommands
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Available commands"
    )

    # init
    subparsers.add_parser(
        "init", help="Initialize the blockchain with the genesis block"
    )

    # add
    add_parser = subparsers.add_parser("add", help="Add new evidence to a case")
    add_parser.add_argument("-c", "--case_id", required=True, help="Case ID (UUID)")
    add_parser.add_argument(
        "-i",
        "--item_id",
        required=True,
        action="append",
        type=ensure_list,
        help="Item ID(s)",
    )
    add_parser.add_argument("-g", "--creator", required=True, help="Creator name")
    add_parser.add_argument("-p", "--password", required=True, help="Creator password")

    # checkout
    checkout_parser = subparsers.add_parser(
        "checkout", help="Checkout an evidence item"
    )
    checkout_parser.add_argument("-i", "--item_id", required=True, help="Item ID")
    checkout_parser.add_argument(
        "-p", "--password", required=True, help="User password"
    )

    # checkin
    checkin_parser = subparsers.add_parser("checkin", help="Checkin an evidence item")
    checkin_parser.add_argument("-i", "--item_id", required=True, help="Item ID")
    checkin_parser.add_argument("-p", "--password", required=True, help="User password")

    # show
    show_parser = subparsers.add_parser("show", help="Display cases, items, or history")
    show_parser.add_argument(
        "type", choices=["cases", "items", "history"], help="What to show"
    )
    show_parser.add_argument("-c", "--case_id", help="Filter by Case ID")
    show_parser.add_argument("-i", "--item_id", help="Filter by Item ID")
    show_parser.add_argument("-n", "--num_entries", type=int, help="Number of entries")
    show_parser.add_argument(
        "-r", "--reverse", action="store_true", help="Show in reverse order"
    )
    show_parser.add_argument("-p", "--password", help="Password for validation")

    # remove
    remove_parser = subparsers.add_parser("remove", help="Remove an evidence item")
    remove_parser.add_argument("-i", "--item_id", required=True, help="Item ID")
    remove_parser.add_argument(
        "-y",
        "--reason",
        "--why",
        required=True,
        choices=["DISPOSED", "DESTROYED", "RELEASED"],
        help="Reason for removal",
    )
    remove_parser.add_argument(
        "-o", "--owner", help="Owner to release to (if reason is RELEASED)"
    )
    remove_parser.add_argument(
        "-p", "--password", required=True, help="Creator password"
    )

    # verify
    verify_parser = subparsers.add_parser(
        "verify", help="Verify the integrity of the blockchain"
    )

    return parser.parse_args()

    # helper  to ensure item_ids is a list


def ensure_list(value):
    if isinstance(value, list):
        return value
    return [value]


def main():
    args = parse_arguments()

    blockchain_path = os.getenv("BCHOC_FILE_PATH", "blockchain.bin")
    blockchain = Blockchain(blockchain_path)

    # print("Current Blockchain")
    # blockchain.print_chain()

    try:
        # Route commands
        if args.command == "init":
            blockchain.initialize()
            print("Blockchain initialized.")
        elif args.command == "add":
            for item_id in args.item_id:
                blockchain.add(args.case_id, item_id, args.creator, args.password)
        elif args.command == "checkout":
            blockchain.checkout(args.item_id, args.password)
            print(f"Item {args.item_id} checked out.")
        elif args.command == "checkin":
            blockchain.checkin(args.item_id, args.password)
            print(f"Item {args.item_id} checked in.")
        elif args.command == "show":
            if args.type == "cases":
                blockchain.show_cases(args.password)
            elif args.type == "items":
                blockchain.show_items(args.case_id, args.password)
            elif args.type == "history":
                blockchain.show_history(
                    args.case_id,
                    args.item_id,
                    args.num_entries,
                    args.reverse,
                    args.password,
                )
        elif args.command == "remove":
            blockchain.remove(args.item_id, args.reason, args.password, args.owner)
            print(f"Item {args.item_id} removed.")
        elif args.command == "verify":
            blockchain.verify()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # print("New Blockchain")
    # blockchain.print_chain()


if __name__ == "__main__":
    main()
