from pathlib import Path
import time


def get_filenames(mode, input_file, output_file=None):
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


def rename_with_prompt(temp_path, final_path):
    # Check if final_path exists and prompt if it does
    while final_path.exists():
        print(f"The file '{final_path}' already exists.")
        new_name = input("Enter a new name for the output file (without extension): ")
        final_path = final_path.with_name(new_name).with_suffix(final_path.suffix)
        
    # Rename temp_path to the confirmed final_path
    temp_path.rename(final_path)
    print(f"File saved as {final_path}")
