import fitz  # PyMuPDF
import sys

def extract_text(pdf_path, output_path):
    with open(output_path, 'w', encoding='utf-8') as f:
        try:
            doc = fitz.open(pdf_path)
            for page in doc:
                f.write(page.get_text())
            print("Successfully extracted using PyMuPDF")
        except Exception as e:
            f.write(f"Error reading with PyMuPDF: {e}\n")
            try:
                import PyPDF2
                with open(pdf_path, 'rb') as file:
                    reader = PyPDF2.PdfReader(file)
                    for page in reader.pages:
                        f.write(page.extract_text())
                print("Successfully extracted using PyPDF2")
            except Exception as e2:
                print(f"Error reading with PyPDF2: {e2}")

if __name__ == "__main__":
    extract_text(sys.argv[1], sys.argv[2])
