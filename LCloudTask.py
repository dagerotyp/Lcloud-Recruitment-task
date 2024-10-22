import argparse
import os
import re
import boto3
from boto3.session import Session 
from botocore.exceptions import ClientError
from typing import List

# Enter AWS Credentials
AWS_ACCESS_KEY_ID = ''
AWS_SECRET_ACESS_KEY = ''

# Initialize Session
session = Session(aws_access_key_id = AWS_ACCESS_KEY_ID, aws_secret_access_key = AWS_SECRET_ACESS_KEY)
s3 = session.resource('s3')

def find_s3_files(bucket_name: str, prefix: str = '') -> List:
	"""Return list of all files stored in an S3 bucket with given prefix"""
	try:
		bucket = s3.Bucket(bucket_name)

		if prefix:
			return bucket.objects.filter(Prefix = prefix)

		else:
			return bucket.objects.all()

	except ClientError as e:
		print(f"Error listing files: {e}")
		return []

def list_s3_files(bucket_name: str, prefix: str = '') -> None:
	"""Prints all files stored in S3 Bucket"""

	s3_files = find_s3_files(bucket_name, prefix)

	if s3_files:
		print(f"Following files were found in bucket_name '{bucket_name}' with prefix: '{prefix}'")
		for file in s3_files:
			print(file.key)
	else:
		print(f"0 files found in bucket: '{bucket_name}' with prefix: '{prefix}'")

def upload_file_to_s3(bucket_name: str, file_path: str, s3_path:str) -> None:
    """Upload a file to the S3 bucket from local machine at specified path"""

    try:
        s3.upload_file(file_path, bucket_name, s3_path)
        print(f"File uploaded successfully: {local_file} -> {s3_path}")

    except FileNotFoundError:
        print(f"The file {local_file} was not found.")

    except ClientError as e:
        print(f"Error uploading file: {e}")

def find_files_with_pattern(files: List, regex_pattern:str) -> List:
	"""Return list of matching objects from S3 response object"""

	match_regex = []
	regex = re.compile(regex_pattern)

	for file in files:
		if regex.search(file.key):
			match_regex.append(file.key)

	return match_regex


def list_s3_files_match_regex(bucket_name:str, regex_pattern:str, prefix: str = '') -> None:
	"""Prints all files in S3 bucket with matching regex"""

	s3_files = find_s3_files(bucket_name, prefix)

	matched = find_files_with_pattern(s3_files, regex_pattern)

	if matched:
		print(f"Following files in bucket: '{bucket_name}' with prefix: '{prefix}' match pattern: '{regex_pattern}':")
		for match in matched:
			print(match)

	else:
		print(f"None of the files in bucket: '{bucket_name}' with prefix: '{prefix}' match pattern: '{regex_pattern}'")


def delete_s3_files_matching_regex(bucket_name: str, regex_pattern: str, prefix: str = '') -> None:
	"""Delete files in an S3 bucket that match a regex"""

	s3_files = find_s3_files(bucket_name, prefix)

	matched = find_files_with_pattern(s3_files, regex_pattern)
        
	if matched:
		print(f"Deleting following files matching '{regex_pattern}' from bucket '{bucket_name}' with prefix: '{prefix}':")
		for match in matched:
			s3.delete_object(Bucket=bucket_name, Key=match)
			print (f"File {match} was deleted")
	else:
		print(f"No files found matching regex: {regex_pattern} found in bucket '{bucket_name}' with prefix '{prefix}'")


def main():
	parser = argparse.ArgumentParser(description="S3 CLI Tool")

	subparsers = parser.add_subparsers(dest="command")

	# List all files
	parser_list = subparsers.add_parser('list', help='List all files in a bucket')
	parser_list.add_argument('--bucket_name', help='S3 bucket name')
	parser_list.add_argument('--prefix', help='S3 bucket prefix')

	# Upload file
	parser_upload = subparsers.add_parser('upload', help='Upload a file to S3')
	parser_upload.add_argument('--bucket_name', help='S3 bucket name')
	parser_upload.add_argument('--local_file', help='Path to the local file')
	parser_upload.add_argument('--s3_file_path', help='Destination path in the S3 bucket')

	# List files matching regex
	parser_list_regex = subparsers.add_parser('list_regex', help='List files matching a regex in the bucket')
	parser_list_regex.add_argument('--bucket_name', help='S3 bucket name')
	parser_list_regex.add_argument('--regex', help='Regex pattern to match')
	parser_list_regex.add_argument('--prefix', help='S3 bucket prefix')

	# Delete files matching regex
	parser_delete_regex = subparsers.add_parser('delete_regex', help='Delete files matching a regex in the bucket')
	parser_delete_regex.add_argument('--bucket_name', help='S3 bucket name')
	parser_delete_regex.add_argument('--regex', help='Regex pattern to match')
	parser_delete_regex.add_argument('--prefix', help='S3 bucket prefix')
	args = parser.parse_args()

	if args.command == 'list':
	    list_s3_files(args.bucket_name, args.prefix)
	elif args.command == 'upload':
	    upload_file_to_s3(args.bucket_name, args.local_file, args.s3_file_path)
	elif args.command == 'list_regex':
	    list_s3_files_match_regex(args.bucket_name, args.regex, args.prefix)
	elif args.command == 'delete_regex':
	    delete_s3_files_matching_regex(args.bucket_name, args.regex, args.prefix)
	else:
	    parser.print_help()

if __name__ == '__main__':
	main()