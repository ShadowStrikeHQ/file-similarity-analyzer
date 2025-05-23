import argparse
import logging
import pathlib
import ssdeep
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Calculates a similarity score between two files using fuzzy hashing (ssdeep).")
    parser.add_argument("file1", type=pathlib.Path, help="Path to the first file.")
    parser.add_argument("file2", type=pathlib.Path, help="Path to the second file.")
    parser.add_argument("-l", "--log_level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level (default: INFO)")
    return parser

def calculate_similarity(file1_path, file2_path):
    """
    Calculates the similarity score between two files using ssdeep fuzzy hashing.

    Args:
        file1_path (pathlib.Path): Path to the first file.
        file2_path (pathlib.Path): Path to the second file.

    Returns:
        int: The similarity score between the two files (0-100). Returns -1 if an error occurs.
    """
    try:
        # Read file content in binary mode
        with open(file1_path, "rb") as f1:
            file1_content = f1.read()
        with open(file2_path, "rb") as f2:
            file2_content = f2.read()

        # Calculate ssdeep hashes
        hash1 = ssdeep.hash(file1_content)
        hash2 = ssdeep.hash(file2_content)

        # Calculate similarity score
        similarity_score = ssdeep.compare(hash1, hash2)

        logging.debug(f"SSDeep hash for {file1_path}: {hash1}")
        logging.debug(f"SSDeep hash for {file2_path}: {hash2}")

        return similarity_score

    except FileNotFoundError:
        logging.error("One or both files not found.")
        return -1
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return -1

def is_valid_file(file_path):
    """
    Checks if the given file path is a valid file.
    Includes checks for file existence and size.
    """
    if not file_path.exists():
        logging.error(f"File not found: {file_path}")
        return False
    if not file_path.is_file():
        logging.error(f"Not a file: {file_path}")
        return False

    try:
        file_size = file_path.stat().st_size
        if file_size == 0:
            logging.warning(f"File is empty: {file_path}")
            return False
        if file_size > 100 * 1024 * 1024: #100MB
            logging.warning(f"File is very large: {file_path}. May impact performance")
    except OSError as e:
        logging.error(f"Error getting file stats for {file_path}: {e}")
        return False

    return True

def calculate_md5(file_path):
    """
    Calculates the MD5 hash of a file. Useful for quick file identity checks.
    """
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logging.error(f"An error occurred while calculating MD5 for {file_path}: {e}")
        return None


def main():
    """
    Main function to execute the file similarity analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set logging level
    logging.getLogger().setLevel(args.log_level.upper())

    file1_path = args.file1
    file2_path = args.file2

    # Input validation
    if not is_valid_file(file1_path):
        exit(1)
    if not is_valid_file(file2_path):
        exit(1)

    md5_file1 = calculate_md5(file1_path)
    md5_file2 = calculate_md5(file2_path)

    if md5_file1 == md5_file2:
        print("Files are identical (same MD5 hash).  Skipping ssdeep")
        exit(0) # Exit normally, files are the same

    # Calculate similarity score
    similarity_score = calculate_similarity(file1_path, file2_path)

    if similarity_score != -1:
        print(f"Similarity score between '{file1_path}' and '{file2_path}': {similarity_score}")
    else:
        print("Failed to calculate similarity score. See logs for details.")
        exit(1) # Exit with error if calculation fails


if __name__ == "__main__":
    # Usage Examples:
    # python main.py file1.txt file2.txt
    # python main.py file1.txt file2.txt -l DEBUG

    main()