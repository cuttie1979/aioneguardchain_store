# Main program
import argparse
import asyncio
from aioneguard.utils import logger_v2
from aioneguard.aioneguardchain.store.core.backend import Backend


def parse_arguments():
    parser = argparse.ArgumentParser(description='AIOneGuardChain StoreCell Console Application',
                                     usage='%(prog)s <command> [options]')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    init_parser = subparsers.add_parser('init', help='Initialize the store')
    init_parser.add_argument('store_backend', choices=['fs', 's3'],
                             help='Storage backend to use (fs for filesystem, s3 for AWS S3)')
    init_parser.add_argument('instance_id', help='Unique identifier for this instance')
    challenge_parser = subparsers.add_parser('challenge', help='Run challenge')
    challenge_parser.add_argument('instance_id', help='Unique identifier for this instance')
    loadadmin_parser = subparsers.add_parser('loadadminresponse', help='Load admin response')
    loadadmin_parser.add_argument('instance_id', help='Unique identifier for this instance')
    loadadmin_parser.add_argument('file_path', help='File path for the admin response')
    start_parser = subparsers.add_parser('start', help='Start the application')
    start_parser.add_argument('instance_id', help='Unique identifier for this instance')
    subparsers.add_parser('help', help='Display help')
    args = parser.parse_args()
    if not args.command:
        parser.error('Please specify a command')
    return args


def main():
    args = parse_arguments()
    _backend = Backend()
    if args.command == 'init':
        logger_v2.log_info(f"Initializing with backend: {args.store_backend}")
        logger_v2.log_info(f"Instance ID: {args.instance_id}")
        _backend.run_init(args.store_backend, args.instance_id)
    elif args.command == 'challenge':
        logger_v2.log_info(f"Running challenge for instance: {args.instance_id}")
        _backend.run_challenge(args.instance_id)
    elif args.command == 'loadadminresponse':
        logger_v2.log_info(f"Loading admin response for instance: {args.instance_id}")
        _backend.run_loadadminresponse(args.instance_id, args.file_path)
    elif args.command == 'start':
        logger_v2.log_info(f"Starting instance: {args.instance_id}")
        try:
            asyncio.run(_backend.run_start(args.instance_id))
        except KeyboardInterrupt:
            pass

    elif args.command == 'help':
        print("Available commands: init, challenge, loadadminresponse, start")


if __name__ == '__main__':
    main()
