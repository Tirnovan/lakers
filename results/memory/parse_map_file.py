import re
import sys

def parse_sections(filename: str) -> dict:
    sections = {}
    
    with open(filename, 'r') as file:
        for line in file:
            if not line.strip().startswith('Section: .text'):
                continue
                
            # Extract all components using regex
            match = re.search(r'Section: \.text, VMA: ([0-9a-f]+), LMA: ([0-9a-f]+), Size: ([0-9a-f]+), Symbol: (.*?)\(\.text\.(.*?)\)', line)
            
            if match:
                vma, lma, size, address, function_name = match.groups()
                
                # Create the entry in the desired format
                sections[function_name] = {
                    "size": int(size, 16),  # Convert hex size to decimal
                    "address": f"0x{vma:0>16}",  # Format address as 0x with leading zeros
                    "compilation_unit": address
                }
    
    # Sort by size
    return dict(sorted(sections.items(), key=lambda x: x[1]["size"], reverse=True))

def write_formatted_json(data: dict, output_file: str):
    with open(output_file, 'w') as f:
        f.write('{\n')
        
        # Get all items except the last one
        items = list(data.items())
        for i, (key, value) in enumerate(items):
            # Write the function name
            f.write(f'    "{key}": \n')
            f.write('    {"size": ' + str(value["size"]) + ',\n')
            f.write('    "address": "' + value["address"] + '",\n')
            f.write('    "compilation_unit": "' + value["compilation_unit"] + '"}')
            
            # Add comma and newlines for all entries except the last one
            if i < len(items) - 1:
                f.write(',\n\n')
            else:
                f.write('\n')
        
        f.write('}\n')

def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_file> ,<output_filename>")
        sys.exit(1)

    filename = sys.argv[1]
    sections = parse_sections(filename)
    
    # Write to output file with custom formatting
    output_filename = sys.argv[2] + '.json'
    write_formatted_json(sections, output_filename)
    
    print(f"Results have been written to {output_filename}")

if __name__ == "__main__":
    main()