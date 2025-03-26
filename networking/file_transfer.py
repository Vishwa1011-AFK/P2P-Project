import logging
import os

logger = logging.getLogger(__name__)

# Removed: TransferState enum (now in TransferManager)
# Removed: FileTransfer class (now in TransferManager)
# Removed: send_file, _send_chunks (now methods in TransferManager)
# Removed: send_folder (now method in TransferManager)
# Removed: update_transfer_progress (now method in TransferManager)
# Removed: compute_hash (now method in TransferManager, could move to utils.py)


def get_files_in_folder(folder_path):
    """
    Recursively collect all files within a given folder.
    Args:
        folder_path: The absolute or relative path to the folder.
    Returns:
        A list of tuples, where each tuple is (full_path_to_file, relative_path_protocol_style).
        Returns an empty list if the folder_path is invalid or empty.
    """
    file_list = []
    if not os.path.isdir(folder_path):
        logger.error(f"Path is not a valid directory: {folder_path}")
        return file_list # Return empty list for invalid input

    logger.debug(f"Scanning folder for files: {folder_path}")
    try:
        for root, _, files in os.walk(folder_path):
            for file in files:
                try:
                     full_path = os.path.join(root, file)
                     # Ensure file is actually accessible before adding? Optional.
                     # if not os.access(full_path, os.R_OK):
                     #     logger.warning(f"Skipping inaccessible file: {full_path}")
                     #     continue

                     # Calculate relative path based on the original folder_path
                     rel_path_os = os.path.relpath(full_path, folder_path)
                     # Convert OS-specific separators (like \ on Windows) to forward slashes '/'
                     # for cross-platform consistency in the protocol and receiving end.
                     rel_path_protocol = rel_path_os.replace(os.sep, '/')
                     file_list.append((full_path, rel_path_protocol))
                except Exception as file_err:
                     logger.error(f"Error processing file '{file}' in '{root}': {file_err}")
                     # Decide whether to skip file or stop scan? Skip for robustness.
    except Exception as walk_err:
        logger.error(f"Error walking directory tree {folder_path}: {walk_err}", exc_info=True)
        # Return whatever was collected so far, or empty list? Empty list might be safer.
        return []

    logger.debug(f"Found {len(file_list)} files in {folder_path}")
    return file_list