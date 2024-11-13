from pathlib import Path
import re
import time


def get_filepaths(mode, input_file, output_file=None):
    input_path = Path("data") / input_file
    base_name = input_path.stem
    original_extension = input_path.suffix.lstrip(".")
    
    if mode == "encrypt":
        temp_path = Path("data") / f"{base_name}_temp_{int(time.time())}.enc"  # Create as a Path object
        metadata = f"EXT:{original_extension}|".encode()

        final_path = (Path("data") / output_file).with_suffix(".enc") if output_file else input_path.with_suffix(".enc")

    elif mode == "decrypt":
        temp_path = Path("data") / f"{base_name}_temp_{int(time.time())}"        
        metadata = None

        final_path = Path("data") / output_file if output_file else input_path

    else:
        raise ValueError("Invalid action or file extension.")

    return metadata, temp_path, final_path


def save_to_file(temp_path, data_to_write, final_path, input_file=None, output_file=None):
    """
    Save data to a temporary file and handle renaming or in-place operations.

    Args:
        temp_path (Path): Path to the temporary file.
        data_to_write (bytes): Data to write to the file.
        final_path (Path): Final path for the output file.
        input_file (str, optional): The original input file name (for in-place operations).
        output_file (str, optional): The user-specified output file name.

    Returns:
        None
    """
    # Validate the output file name if provided
    if output_file and not is_valid_filename(output_file):
        print(f"Error: Invalid filename '{output_file}'.")
        return

    # Write to the temporary file
    with temp_path.open(mode="wb") as file:
        file.write(data_to_write)
    print(f"Temporary file created: {temp_path}")

    # Handle in-place encryption/decryption
    if output_file is None and input_file:
        input_path = Path("data") / input_file
        print(f"In-place operation: '{input_path}' will be replaced.")
        input_path.unlink()  # Remove the original file

    rename_with_prompt(temp_path, final_path)


def rename_with_prompt(temp_path, final_path, prompt_message="Enter a new name for the output file (without extension): "):
    """
    Renames a temporary file to the final path, prompting the user for a new name if a conflict exists.

    Args:
        temp_path (Path): Path to the temporary file.
        final_path (Path): Desired final path for the file.
        prompt_message (str): Customizable message for renaming prompt.

    Returns:
        Path: The final path to which the file was renamed.
    """
    while final_path.exists():
        print(f"The file '{final_path}' already exists.")
        new_name = input(prompt_message).strip()
        if is_valid_filename(new_name):  # Validate the filename
            final_path = final_path.with_name(new_name).with_suffix(final_path.suffix)
        else:
            print("Invalid filename. Please use only alphanumeric characters, underscores, or hyphens.")
    temp_path.rename(final_path)
    print(f"File saved as {final_path}")
    return final_path


def is_valid_filename(filename):
    """
    Checks if a filename is valid.

    Args:
        filename (str): The filename to validate.

    Returns:
        bool: True if the filename is valid, False otherwise.
    """
    # Allow alphanumeric, underscores, hyphens, and spaces
    return re.match(r'^[\w\- ]+(\.[\w]+)?$', filename) is not None