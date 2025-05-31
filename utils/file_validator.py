import os
import magic
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'exe', 'dll', 'doc', 'docx', 'pdf', 'xls', 'xlsx', 'txt', 'ppt', 'pptx'}
# Parse MAX_CONTENT_LENGTH properly, handling potential comment in the value
try:
    max_content_length = os.environ.get('MAX_CONTENT_LENGTH', '10485760')  # Default: 10MB
    MAX_FILE_SIZE = int(max_content_length.split('#')[0].strip())
except (ValueError, AttributeError):
    MAX_FILE_SIZE = 10 * 1024 * 1024  # Default to 10MB if parsing fails

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
    elif extension in ['ppt', 'pptx'] and 'Microsoft PowerPoint' not in file_type:
        return False
    elif extension == 'txt' and 'text' not in file_type.lower():
        return False

    return True
