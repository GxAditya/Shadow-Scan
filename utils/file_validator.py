import os
import magic
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'exe', 'dll', 'doc', 'docx', 'pdf', 'xls', 'xlsx'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file(file):
    # Check if file exists
    if not file:
        return False

    # Check filename
    if not allowed_file(file.filename):
        return False

    # Check file size
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > MAX_FILE_SIZE:
        return False

    # Check file type using magic
    file_type = magic.from_buffer(file.read(2048))
    file.seek(0)

    # Validate file type matches extension
    extension = file.filename.rsplit('.', 1)[1].lower()
    if extension == 'exe' and 'PE32' not in file_type:
        return False
    elif extension in ['doc', 'docx'] and 'Microsoft Word' not in file_type:
        return False
    elif extension == 'pdf' and 'PDF' not in file_type:
        return False
    elif extension in ['xls', 'xlsx'] and 'Microsoft Excel' not in file_type:
        return False

    return True
