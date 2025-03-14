import hashlib
import json
import os
import sys
from typing import Any, TextIO, Union


def calculate_file_hash(
    filepath: str, hash_algorithm: str = "sha256", buffer_size: int = 65536
) -> str:
    """
    Calculate hash of a file using specified algorithm.
    For .metadata files, ignore the last line (timestamp).

    Args:
        filepath: Path to the file
        hash_algorithm: Algorithm to use ('md5', 'sha1', 'sha256', etc.)
        buffer_size: Size of chunks to read from file

    Returns:
        String representation of the file hash
    """
    hash_func = hashlib.new(hash_algorithm)

    # Special handling for metadata files
    filename = os.path.basename(filepath)
    is_metadata = filename == ".metadata" or filename.endswith(".metadata")

    if is_metadata:
        # For metadata files, read all lines except the last one (timestamp)
        with open(filepath, "rb") as f:
            lines = f.readlines()

        # Skip the last line if it exists
        if lines:
            content_to_hash = b"".join(lines[:-1])
            hash_func.update(content_to_hash)
    else:
        # Standard file processing
        with open(filepath, "rb") as f:
            while True:
                data = f.read(buffer_size)
                if not data:
                    break
                hash_func.update(data)

    return hash_func.hexdigest()


def generate_folder_structure(
    root_path: str, hash_algorithm: str = "sha256"
) -> dict[str, Any]:
    """
    Recursively traverse directory and generate structure with file hashes.

    Args:
        root_path: Path to the root directory
        hash_algorithm: Algorithm to use for file hashing

    Returns:
        dictionary representing folder structure with file hashes
    """
    structure = {
        "type": "directory",
        "name": os.path.basename(root_path),
        "contents": [],
    }

    try:
        items = sorted(os.listdir(root_path))

        for item in items:
            item_path = os.path.join(root_path, item)

            if os.path.isdir(item_path):
                # Recursively process subdirectory
                subdir_structure = generate_folder_structure(item_path, hash_algorithm)
                structure["contents"].append(subdir_structure)
            else:
                # Process file
                try:
                    file_hash = calculate_file_hash(item_path, hash_algorithm)
                    file_info = {
                        "type": "file",
                        "name": item,
                        "hash": file_hash,
                        "algorithm": hash_algorithm,
                        "size": os.path.getsize(item_path),
                    }
                    structure["contents"].append(file_info)
                except Exception as e:
                    # Handle files that can't be read
                    file_info = {"type": "file", "name": item, "error": str(e)}
                    structure["contents"].append(file_info)

    except Exception as e:
        structure["error"] = str(e)

    return structure


def save_structure_to_json(structure: dict[str, Any], output_file: str) -> None:
    """
    Save folder structure to JSON file.

    Args:
        structure: dictionary representing folder structure
        output_file: Path to output JSON file
    """
    with open(output_file, "w") as f:
        json.dump(structure, f, indent=2)


def load_structure_from_json(json_file: str) -> dict[str, Any]:
    """
    Load folder structure from JSON file.

    Args:
        json_file: Path to JSON file

    Returns:
        dictionary representing folder structure
    """
    with open(json_file, "r") as f:
        return json.load(f)


def validate_structure(
    current_path: str, baseline_structure: dict[str, Any]
) -> dict[str, Any]:
    """
    Validate current folder structure against baseline.

    Args:
        current_path: Path to the directory to validate
        baseline_structure: Baseline structure to compare against

    Returns:
        dictionary with validation results
    """
    # Extract algorithm from baseline
    hash_algorithm = None
    for item in baseline_structure.get("contents", []):
        if item.get("type") == "file" and "algorithm" in item:
            hash_algorithm = item["algorithm"]
            break

    hash_algorithm = hash_algorithm or "sha256"

    # Generate current structure
    current_structure = generate_folder_structure(current_path, hash_algorithm)

    # Compare structures
    return compare_structures(baseline_structure, current_structure)


def compare_structures(
    baseline: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    """
    Compare two folder structures.

    Args:
        baseline: Baseline structure
        current: Current structure

    Returns:
        dictionary with comparison results
    """
    results = {"matches": True, "differences": []}

    # Check if types match
    if baseline.get("type") != current.get("type"):
        results["matches"] = False
        results["differences"].append(
            f"Type mismatch: {baseline.get('name')} - expected {baseline.get('type')}, got {current.get('type')}"
        )
        return results

    # Check if names match
    if baseline.get("name") != current.get("name"):
        results["matches"] = False
        results["differences"].append(
            f"Name mismatch: expected {baseline.get('name')}, got {current.get('name')}"
        )

    # If it's a file, check hash
    if baseline.get("type") == "file":
        if baseline.get("hash") != current.get("hash"):
            results["matches"] = False
            results["differences"].append(
                f"Hash mismatch for file {baseline.get('name')}: expected {baseline.get('hash')}, got {current.get('hash')}"
            )

        if baseline.get("size") != current.get("size"):
            results["matches"] = False
            results["differences"].append(
                f"Size mismatch for file {baseline.get('name')}: expected {baseline.get('size')}, got {current.get('size')}"
            )

    # If it's a directory, check contents
    elif baseline.get("type") == "directory":
        baseline_contents = {
            item["name"]: item for item in baseline.get("contents", [])
        }
        current_contents = {item["name"]: item for item in current.get("contents", [])}

        # Check for missing files/directories
        for name, item in baseline_contents.items():
            if name not in current_contents:
                results["matches"] = False
                results["differences"].append(f"Missing item: {name}")
            else:
                # Recursively compare the item
                sub_result = compare_structures(item, current_contents[name])
                if not sub_result["matches"]:
                    results["matches"] = False
                    results["differences"].extend(sub_result["differences"])

        # Check for extra files/directories
        for name in current_contents:
            if name not in baseline_contents:
                results["matches"] = False
                results["differences"].append(f"Extra item: {name}")

    return results


def print_directory_tree(
    structure: dict[str, Any],
    output: Union[TextIO, str] = sys.stdout,
    show_hashes: bool = False,
    prefix: str = "",
    last_item: bool = True,
    is_root: bool = True,
) -> None:
    """
    Print a human-readable directory tree from the structure dictionary.

    Args:
        structure: dictionary representing folder structure
        output: File object or path to output file (default: sys.stdout)
        show_hashes: Whether to show file hashes
        prefix: Prefix for the current line (used for recursion)
        last_item: Whether this is the last item in its parent directory (used for recursion)
        is_root: Whether this is the root directory
    """
    # Open file if a path string was provided
    close_file = False
    if isinstance(output, str):
        output = open(output, "w")
        close_file = True

    try:
        # Determine the symbols to use
        if is_root:
            # Root directory
            line = structure.get("name", "Root")
            output.write(f"{line}\n")
            new_prefix = ""
        else:
            # Non-root items
            item_prefix = "└── " if last_item else "├── "
            line = item_prefix + structure.get("name", "")

            # Add hash info if it's a file and hashes should be shown
            if structure.get("type") == "file" and show_hashes and "hash" in structure:
                short_hash = structure["hash"][:8] + "..." + structure["hash"][-8:]
                size_str = f"{structure.get('size', 0) / 1024:.1f} KB"
                line += f" ({short_hash}, {size_str})"

            # Add error info if present
            if "error" in structure:
                line += f" [ERROR: {structure['error']}]"

            output.write(f"{prefix}{line}\n")

            # Prepare prefix for children
            new_prefix = prefix + ("    " if last_item else "│   ")

        # If it's a directory, process its contents
        if structure.get("type") == "directory" and "contents" in structure:
            contents = structure.get("contents", [])
            for i, item in enumerate(contents):
                is_last = i == len(contents) - 1
                print_directory_tree(
                    item, output, show_hashes, new_prefix, is_last, False
                )

    finally:
        # Close the file if we opened it
        if close_file:
            output.close()


def save_directory_tree(
    structure: dict[str, Any], output_file: str, show_hashes: bool = False
) -> None:
    """
    Save a human-readable directory tree to a file.

    Args:
        structure: dictionary representing folder structure
        output_file: Path to output file
        show_hashes: Whether to show file hashes
    """
    print_directory_tree(structure, output_file, show_hashes)


def main() -> None:
    """
    Main function to demonstrate usage.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Folder structure hash validator")
    parser.add_argument(
        "action", choices=["generate", "validate"], help="Action to perform"
    )
    parser.add_argument("path", help="Path to directory")
    parser.add_argument("--output", "-o", help="Output JSON file (for generate)")
    parser.add_argument("--baseline", "-b", help="Baseline JSON file (for validate)")
    parser.add_argument(
        "--algorithm", "-a", default="sha256", help="Hash algorithm to use"
    )

    args = parser.parse_args()

    if args.action == "generate":
        if not args.output:
            parser.error("--output is required for generate action")

        structure = generate_folder_structure(args.path, args.algorithm)
        save_structure_to_json(structure, args.output)
        print(f"Structure saved to {args.output}")

    elif args.action == "validate":
        if not args.baseline:
            parser.error("--baseline is required for validate action")

        baseline = load_structure_from_json(args.baseline)
        results = validate_structure(args.path, baseline)

        if results["matches"]:
            print("Validation passed! Folder structure matches baseline.")
        else:
            print("Validation failed! Differences found:")
            for diff in results["differences"]:
                print(f"- {diff}")

    elif args.action == "tree":
        # If path is a directory, generate structure first
        if os.path.isdir(args.path):
            structure = generate_folder_structure(args.path, args.algorithm)
        # If path is a JSON file, load structure from it
        else:
            structure = load_structure_from_json(args.path)

        # Print tree to output file or stdout
        if args.output:
            save_directory_tree(structure, args.output, args.show_hashes)
            print(f"Directory tree saved to {args.output}")
        else:
            print_directory_tree(structure, show_hashes=args.show_hashes)


if __name__ == "__main__":
    main()
