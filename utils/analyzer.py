import yara
import pefile
import magic
import os
import logging
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class RiskFactor:
    def __init__(self, name: str, description: str, severity: str, category: str):
        self.name = name
        self.description = description
        self.severity = severity
        self.category = category

    def to_dict(self) -> Dict[str, str]:
        return {
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'category': self.category
        }

def load_yara_rules():
    rules_path = Path(__file__).parent.parent / 'static/yara_rules/malware_rules.yar'
    try:
        return yara.compile(str(rules_path))
    except Exception as e:
        logger.error(f"Error loading YARA rules: {str(e)}")
        return None

def analyze_pe_imports(pe) -> List[RiskFactor]:
    risk_factors = []
    suspicious_imports = {
        # Memory Operations - High Risk
        'VirtualAlloc': ('Memory allocation', 'Could be used for shellcode injection', 'high'),
        'VirtualAllocEx': ('Remote memory allocation', 'Used in process injection attacks', 'high'),
        'VirtualProtect': ('Memory protection', 'Can modify memory permissions for code execution', 'high'),
        'VirtualProtectEx': ('Remote memory protection', 'Used to make injected code executable', 'high'),
        'WriteProcessMemory': ('Process manipulation', 'Indicates potential process tampering', 'high'),
        'ReadProcessMemory': ('Process manipulation', 'Reading memory from other processes', 'high'),
        
        # Thread and Process Operations - High Risk
        'CreateRemoteThread': ('Process manipulation', 'Common in code injection techniques', 'high'),
        'CreateThread': ('Thread creation', 'Could be used for concurrent malicious activities', 'medium'),
        'NtCreateThreadEx': ('Low-level thread creation', 'Advanced injection technique', 'high'),
        'RtlCreateUserThread': ('User thread creation', 'Advanced injection technique', 'high'),
        'QueueUserAPC': ('Asynchronous procedure call', 'Code injection via APC', 'high'),
        'SetThreadContext': ('Thread manipulation', 'Process hollowing technique', 'high'),
        'GetThreadContext': ('Thread inspection', 'Process hollowing technique', 'high'),
        'SuspendThread': ('Thread suspension', 'Used in process hollowing', 'medium'),
        'ResumeThread': ('Thread resumption', 'Used in process hollowing', 'medium'),
        
        # Dynamic Loading - Medium to High Risk
        'LoadLibrary': ('Dynamic loading', 'May load malicious DLLs', 'medium'),
        'LoadLibraryEx': ('Extended dynamic loading', 'May load malicious DLLs', 'medium'),
        'GetProcAddress': ('Function resolution', 'Dynamic API resolution, often obfuscated', 'medium'),
        'LdrLoadDll': ('Low-level DLL loading', 'Advanced technique to load DLLs', 'high'),
        
        # System Hooks - High Risk
        'SetWindowsHookEx': ('System hooks', 'Could be used for keylogging', 'high'),
        'UnhookWindowsHookEx': ('Hook removal', 'Cleanup after hooking', 'medium'),
        
        # Registry Operations - Medium Risk
        'RegCreateKey': ('Registry manipulation', 'Registry modifications', 'medium'),
        'RegSetValue': ('Registry modification', 'Writing to registry', 'medium'),
        'RegDeleteKey': ('Registry deletion', 'Removing registry keys', 'medium'),
        'RegOpenKey': ('Registry access', 'Reading registry values', 'low'),
        
        # Network Operations - Medium to High Risk
        'WSAStartup': ('Network initialization', 'Network capability initialization', 'medium'),
        'WSASocket': ('Network activity', 'Raw socket operations', 'high'),
        'socket': ('Socket creation', 'Network communication', 'medium'),
        'connect': ('Network connection', 'Outbound network connection', 'medium'),
        'send': ('Data transmission', 'Sending data over network', 'low'),
        'recv': ('Data reception', 'Receiving data from network', 'low'),
        'bind': ('Socket binding', 'Binding to network port', 'medium'),
        'listen': ('Socket listening', 'Listening for connections (backdoor)', 'high'),
        'accept': ('Connection acceptance', 'Accepting connections (backdoor)', 'high'),
        'InternetOpen': ('Internet activity', 'Internet connectivity', 'medium'),
        'InternetConnect': ('Internet connection', 'Establishing internet connection', 'medium'),
        'InternetOpenUrl': ('URL opening', 'Opening remote URLs', 'medium'),
        'HttpSendRequest': ('HTTP request', 'Sending HTTP requests', 'medium'),
        'HttpQueryInfo': ('HTTP query', 'Querying HTTP information', 'low'),
        'URLDownloadToFile': ('File download', 'Downloading files from internet', 'high'),
        'WinHttpOpen': ('WinHTTP', 'HTTP operations', 'medium'),
        'FtpPutFile': ('FTP upload', 'Uploading files via FTP', 'high'),
        'FtpGetFile': ('FTP download', 'Downloading files via FTP', 'medium'),
        
        # Cryptographic Operations - Low to Medium Risk
        'CryptEncrypt': ('Cryptographic', 'Data encryption capability', 'medium'),
        'CryptDecrypt': ('Cryptographic', 'Data decryption capability', 'medium'),
        'CryptAcquireContext': ('Crypto context', 'Cryptographic context initialization', 'low'),
        'CryptCreateHash': ('Hash creation', 'Creating cryptographic hash', 'low'),
        'CryptHashData': ('Hashing', 'Hashing data', 'low'),
        'CryptDeriveKey': ('Key derivation', 'Deriving encryption keys', 'medium'),
        
        # File Operations - Low to Medium Risk
        'CreateFile': ('File creation', 'Creating or opening files', 'low'),
        'WriteFile': ('File writing', 'Writing to files', 'low'),
        'ReadFile': ('File reading', 'Reading from files', 'low'),
        'DeleteFile': ('File deletion', 'Deleting files', 'medium'),
        'MoveFile': ('File moving', 'Moving or renaming files', 'low'),
        'CopyFile': ('File copying', 'Copying files', 'low'),
        'FindFirstFile': ('File enumeration', 'Searching for files', 'low'),
        'FindNextFile': ('File enumeration', 'Iterating through files', 'low'),
        'GetFileAttributes': ('File inspection', 'Getting file attributes', 'low'),
        'SetFileAttributes': ('File modification', 'Modifying file attributes', 'medium'),
        
        # Process Operations - Medium Risk
        'CreateProcess': ('Process creation', 'Creating new processes', 'medium'),
        'ShellExecute': ('Shell execution', 'Executing commands or files', 'high'),
        'WinExec': ('Program execution', 'Executing programs', 'high'),
        'OpenProcess': ('Process access', 'Opening process handle', 'medium'),
        'TerminateProcess': ('Process termination', 'Killing processes', 'medium'),
        'GetModuleHandle': ('Module handle', 'Getting module handle', 'low'),
        'GetModuleFileName': ('Module path', 'Getting module file path', 'low'),
        
        # Service Operations - Medium to High Risk
        'OpenSCManager': ('Service manager', 'Accessing service control manager', 'medium'),
        'CreateService': ('Service creation', 'Creating Windows service (persistence)', 'high'),
        'StartService': ('Service start', 'Starting Windows service', 'medium'),
        'ControlService': ('Service control', 'Controlling service state', 'medium'),
        'DeleteService': ('Service deletion', 'Deleting service', 'medium'),
        
        # Anti-Debug/Anti-Analysis - High Risk
        'IsDebuggerPresent': ('Anti-debug', 'Checking for debugger', 'high'),
        'CheckRemoteDebuggerPresent': ('Anti-debug', 'Remote debugger detection', 'high'),
        'OutputDebugString': ('Debug output', 'Can be used for anti-debug', 'medium'),
        'NtQueryInformationProcess': ('Process info', 'Querying process information (anti-debug)', 'high'),
        'ZwQueryInformationProcess': ('Process info', 'Querying process information (anti-debug)', 'high'),
        
        # System Information - Low to Medium Risk
        'GetSystemInfo': ('System info', 'Getting system information', 'low'),
        'GetVersionEx': ('Version info', 'Getting OS version', 'low'),
        'GetComputerName': ('Computer name', 'Getting computer name', 'low'),
        'GetUserName': ('User name', 'Getting user name', 'low'),
        
        # Clipboard Operations - Medium Risk
        'GetClipboardData': ('Clipboard access', 'Reading clipboard data', 'medium'),
        'SetClipboardData': ('Clipboard modification', 'Writing to clipboard', 'low'),
        'OpenClipboard': ('Clipboard access', 'Opening clipboard', 'low'),
        
        # Screenshot/Screen Capture - High Risk for spyware
        'GetDC': ('Device context', 'Getting device context (screenshot)', 'medium'),
        'BitBlt': ('Bitmap transfer', 'Copying bitmaps (screenshot)', 'high'),
        'CreateCompatibleBitmap': ('Bitmap creation', 'Creating bitmap (screenshot)', 'medium'),
        
        # Driver/Kernel Operations - Very High Risk
        'ZwLoadDriver': ('Driver loading', 'Loading kernel driver', 'high'),
        'NtLoadDriver': ('Driver loading', 'Loading kernel driver', 'high'),
        'DeviceIoControl': ('Device I/O', 'Direct device communication', 'medium'),
    }

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imp_name = imp.name.decode() if isinstance(imp.name, bytes) else str(imp.name)
                    for sus_import, (category, desc, severity) in suspicious_imports.items():
                        if sus_import.lower() in imp_name.lower():
                            risk_factors.append(RiskFactor(
                                name=f"Suspicious Import: {imp_name}",
                                description=desc,
                                severity=severity,
                                category=category
                            ))
    return risk_factors

def analyze_pe_sections(pe) -> List[RiskFactor]:
    risk_factors = []
    for section in pe.sections:
        section_name = section.Name.decode().rstrip('\x00')
        entropy = section.get_entropy()

        if entropy > 7:
            risk_factors.append(RiskFactor(
                name=f"High entropy in section {section_name}",
                description=f"Section entropy ({entropy:.2f}) indicates potential encryption or packing",
                severity="high",
                category="Anti-Analysis"
            ))

        if section.Characteristics & 0xE0000000:
            risk_factors.append(RiskFactor(
                name=f"Suspicious section permissions: {section_name}",
                description="Section has execute, write, and read permissions",
                severity="medium",
                category="Code Behavior"
            ))
    return risk_factors

def analyze_pe_characteristics(pe) -> List[RiskFactor]:
    risk_factors = []

    if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040 == 0:
        risk_factors.append(RiskFactor(
            name="ASLR Disabled",
            description="Address Space Layout Randomization is disabled, making exploitation easier",
            severity="high",
            category="Security Features"
        ))

    if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400 == 0:
        risk_factors.append(RiskFactor(
            name="DEP Disabled",
            description="Data Execution Prevention is disabled, allowing code execution in data pages",
            severity="high",
            category="Security Features"
        ))

    return risk_factors

def analyze_pe_resources(pe) -> List[RiskFactor]:
    """Analyze PE resources for suspicious patterns"""
    risk_factors = []
    
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data_rva = resource_lang.data.struct.OffsetToData
                                size = resource_lang.data.struct.Size
                                
                                # Check for unusually large resources
                                if size > 1000000:  # 1MB
                                    risk_factors.append(RiskFactor(
                                        name="Large Resource Section",
                                        description=f"Resource section is unusually large ({size} bytes), may contain embedded payload",
                                        severity="medium",
                                        category="Resources"
                                    ))
        except Exception as e:
            logger.debug(f"Error analyzing resources: {str(e)}")
    
    return risk_factors

def analyze_pe_exports(pe) -> List[RiskFactor]:
    """Analyze PE exports for suspicious patterns"""
    risk_factors = []
    
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        suspicious_exports = ['DllRegisterServer', 'DllInstall', 'ServiceMain', 'DriverEntry']
        
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exp_name = exp.name.decode() if isinstance(exp.name, bytes) else str(exp.name)
                if any(sus in exp_name for sus in suspicious_exports):
                    risk_factors.append(RiskFactor(
                        name=f"Suspicious Export: {exp_name}",
                        description="Export function commonly used in malware or system hooks",
                        severity="medium",
                        category="Exports"
                    ))
    
    return risk_factors

def detect_packer(pe) -> List[RiskFactor]:
    """Detect known packers and obfuscation"""
    risk_factors = []
    
    packer_signatures = {
        b'UPX': ('UPX Packer', 'File is packed with UPX, common in malware'),
        b'MPRESS': ('MPRESS Packer', 'File is packed with MPRESS'),
        b'PECompact': ('PECompact', 'File is packed with PECompact'),
        b'ASPack': ('ASPack', 'File is packed with ASPack'),
        b'.nsp': ('NsPack', 'File is packed with NsPack'),
        b'Themida': ('Themida', 'File is protected with Themida'),
        b'VMProtect': ('VMProtect', 'File is protected with VMProtect'),
        b'Obsidium': ('Obsidium', 'File is protected with Obsidium'),
    }
    
    # Check section names for packer signatures
    for section in pe.sections:
        section_name = section.Name.strip(b'\x00')
        for sig, (packer_name, desc) in packer_signatures.items():
            if sig in section_name:
                risk_factors.append(RiskFactor(
                    name=f"Packer Detected: {packer_name}",
                    description=desc,
                    severity="high",
                    category="Obfuscation"
                ))
    
    return risk_factors

def analyze_pe_anomalies(pe) -> List[RiskFactor]:
    """Detect various PE anomalies"""
    risk_factors = []
    
    # Check for unusual entry point
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for section in pe.sections:
        if (entry_point >= section.VirtualAddress and 
            entry_point < section.VirtualAddress + section.Misc_VirtualSize):
            section_name = section.Name.decode().rstrip('\x00')
            if section_name not in ['.text', 'CODE', '.code']:
                risk_factors.append(RiskFactor(
                    name=f"Unusual Entry Point in {section_name}",
                    description="Entry point is not in typical code section, possible packing or obfuscation",
                    severity="high",
                    category="PE Structure"
                ))
            break
    
    # Check for suspicious compile timestamp
    compile_time = pe.FILE_HEADER.TimeDateStamp
    if compile_time < 946684800:  # Before year 2000
        risk_factors.append(RiskFactor(
            name="Suspicious Compile Timestamp",
            description="File has a compile timestamp before year 2000, may be forged",
            severity="medium",
            category="PE Structure"
        ))
    elif compile_time > datetime.now().timestamp():
        risk_factors.append(RiskFactor(
            name="Future Compile Timestamp",
            description="File has a compile timestamp in the future, likely forged",
            severity="medium",
            category="PE Structure"
        ))
    
    # Check for TLS callbacks (used for anti-debugging)
    if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        risk_factors.append(RiskFactor(
            name="TLS Callbacks Present",
            description="File uses TLS callbacks, often used for anti-debugging",
            severity="medium",
            category="Anti-Analysis"
        ))
    
    return risk_factors

def analyze_pe_file(filepath):
    try:
        pe = pefile.PE(filepath)
        risk_factors = []

        # Collect risk factors from different analyses
        risk_factors.extend(analyze_pe_imports(pe))
        risk_factors.extend(analyze_pe_sections(pe))
        risk_factors.extend(analyze_pe_characteristics(pe))
        risk_factors.extend(analyze_pe_resources(pe))
        risk_factors.extend(analyze_pe_exports(pe))
        risk_factors.extend(detect_packer(pe))
        risk_factors.extend(analyze_pe_anomalies(pe))

        return {
            'risk_factors': [rf.__dict__ for rf in risk_factors],
            'machine_type': hex(pe.FILE_HEADER.Machine),
            'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'compile_time': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat() if pe.FILE_HEADER.TimeDateStamp else None
        }
    except Exception as e:
        logger.error(f"Error analyzing PE file: {str(e)}")
        return None

def analyze_document(filepath: str, file_type: str) -> List[RiskFactor]:
    risk_factors = []

    # Check for potential macro-enabled documents
    if any(ext in file_type.lower() for ext in ['word', 'excel', 'powerpoint']):
        risk_factors.append(RiskFactor(
            name="Macro-Enabled Document",
            description="Document may contain potentially malicious macros",
            severity="medium",
            category="Document Features"
        ))

    # Check for embedded objects
    if "OLE" in file_type or "Composite Document" in file_type:
        risk_factors.append(RiskFactor(
            name="Embedded Objects",
            description="Document contains embedded objects which could be malicious",
            severity="medium",
            category="Document Features"
        ))
    
    # Check for suspicious PDF patterns
    if "PDF" in file_type:
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
                
                # Check for JavaScript in PDF
                if b'/JavaScript' in content or b'/JS' in content:
                    risk_factors.append(RiskFactor(
                        name="JavaScript in PDF",
                        description="PDF contains JavaScript which could be malicious",
                        severity="high",
                        category="Document Features"
                    ))
                
                # Check for auto-actions in PDF
                if b'/AA' in content or b'/OpenAction' in content:
                    risk_factors.append(RiskFactor(
                        name="Auto-Action in PDF",
                        description="PDF contains auto-execute actions that run when opened",
                        severity="high",
                        category="Document Features"
                    ))
                
                # Check for launch actions
                if b'/Launch' in content:
                    risk_factors.append(RiskFactor(
                        name="Launch Action in PDF",
                        description="PDF can launch external programs",
                        severity="high",
                        category="Document Features"
                    ))
                
                # Check for embedded files
                if b'/EmbeddedFile' in content:
                    risk_factors.append(RiskFactor(
                        name="Embedded Files in PDF",
                        description="PDF contains embedded files which could be malicious",
                        severity="medium",
                        category="Document Features"
                    ))
        except Exception as e:
            logger.debug(f"Error analyzing PDF: {str(e)}")

    return risk_factors

def analyze_script_file(filepath: str, file_type: str, filename: str) -> List[RiskFactor]:
    """Analyze script files for malicious patterns"""
    risk_factors = []
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(100000)  # Read first 100KB
            content_lower = content.lower()
            
            # PowerShell specific checks
            if any(ext in filename.lower() for ext in ['.ps1', '.psm1']):
                if 'invoke-expression' in content_lower or 'iex' in content_lower:
                    risk_factors.append(RiskFactor(
                        name="PowerShell Code Execution",
                        description="Script uses Invoke-Expression which can execute arbitrary code",
                        severity="high",
                        category="Script Behavior"
                    ))
                
                if 'downloadstring' in content_lower or 'downloadfile' in content_lower:
                    risk_factors.append(RiskFactor(
                        name="PowerShell Download",
                        description="Script downloads content from the internet",
                        severity="high",
                        category="Script Behavior"
                    ))
                
                if '-encodedcommand' in content_lower or '-enc' in content_lower:
                    risk_factors.append(RiskFactor(
                        name="Encoded PowerShell Command",
                        description="Script uses encoded commands, often used to hide malicious code",
                        severity="high",
                        category="Obfuscation"
                    ))
                
                if 'bypass' in content_lower and 'executionpolicy' in content_lower:
                    risk_factors.append(RiskFactor(
                        name="Execution Policy Bypass",
                        description="Script attempts to bypass execution policy",
                        severity="high",
                        category="Script Behavior"
                    ))
            
            # VBScript / JScript checks
            if any(ext in filename.lower() for ext in ['.vbs', '.vbe', '.js', '.jse']):
                if 'wscript.shell' in content_lower or 'shell.application' in content_lower:
                    risk_factors.append(RiskFactor(
                        name="Shell Execution",
                        description="Script can execute shell commands",
                        severity="high",
                        category="Script Behavior"
                    ))
                
                if 'adodb.stream' in content_lower:
                    risk_factors.append(RiskFactor(
                        name="File Stream Operations",
                        description="Script can write binary files to disk",
                        severity="high",
                        category="Script Behavior"
                    ))
                
                if 'msxml2.xmlhttp' in content_lower or 'microsoft.xmlhttp' in content_lower:
                    risk_factors.append(RiskFactor(
                        name="HTTP Requests",
                        description="Script makes HTTP requests",
                        severity="medium",
                        category="Network Activity"
                    ))
            
            # Batch file checks
            if any(ext in filename.lower() for ext in ['.bat', '.cmd']):
                if 'reg add' in content_lower or 'reg delete' in content_lower:
                    risk_factors.append(RiskFactor(
                        name="Registry Modification",
                        description="Batch file modifies Windows registry",
                        severity="medium",
                        category="System Modification"
                    ))
                
                if 'powershell' in content_lower:
                    risk_factors.append(RiskFactor(
                        name="PowerShell Execution",
                        description="Batch file executes PowerShell commands",
                        severity="medium",
                        category="Script Behavior"
                    ))
            
            # Common suspicious patterns across all scripts
            suspicious_patterns = {
                'eval(': ('Code Evaluation', 'Script uses eval to execute code dynamically', 'high'),
                'exec(': ('Code Execution', 'Script executes arbitrary code', 'high'),
                'base64': ('Base64 Encoding', 'Script uses base64 encoding, often to hide content', 'medium'),
                'fromcharcode': ('Character Code Obfuscation', 'Script uses character codes to hide strings', 'medium'),
                'unescape': ('URL Decoding', 'Script decodes URLs or strings', 'medium'),
            }
            
            for pattern, (name, desc, severity) in suspicious_patterns.items():
                if pattern in content_lower:
                    risk_factors.append(RiskFactor(
                        name=name,
                        description=desc,
                        severity=severity,
                        category="Script Patterns"
                    ))
    
    except Exception as e:
        logger.debug(f"Error analyzing script file: {str(e)}")
    
    return risk_factors

def analyze_archive_file(filepath: str, file_type: str) -> List[RiskFactor]:
    """Analyze archive files for suspicious patterns"""
    risk_factors = []
    
    # Basic archive detection
    if any(archive_type in file_type.lower() for archive_type in ['zip', 'rar', '7-zip', 'gzip', 'tar']):
        risk_factors.append(RiskFactor(
            name="Archive File",
            description="File is an archive and may contain hidden malicious content",
            severity="low",
            category="File Type"
        ))
        
        # Check for password-protected archives (common in malware delivery)
        if 'encrypted' in file_type.lower():
            risk_factors.append(RiskFactor(
                name="Encrypted Archive",
                description="Archive is password-protected, commonly used to evade detection",
                severity="medium",
                category="Archive Features"
            ))
    
    return risk_factors

def analyze_file(filepath):
    results = {
        'verdict': 'Clean',
        'risk_level': 'low',
        'risk_factors': [],
        'file_type': '',
        'analysis_details': {}
    }

    try:
        # Get file type
        file_type = magic.from_file(filepath)
        results['file_type'] = file_type
        
        # Get filename
        filename = os.path.basename(filepath)

        # Initialize risk factors list
        all_risk_factors = []

        # Load YARA rules
        rules = load_yara_rules()
        if rules:
            matches = rules.match(filepath)
            if matches:
                for match in matches:
                    all_risk_factors.append(RiskFactor(
                        name=f"YARA Rule Match: {match.rule}",
                        description=match.meta.get('description', 'Matched malicious pattern'),
                        severity=match.meta.get('severity', 'high'),
                        category="Malware Patterns"
                    ))

        # Additional PE analysis for executables
        if 'PE32' in file_type or 'MS-DOS executable' in file_type:
            pe_analysis = analyze_pe_file(filepath)
            if pe_analysis:
                results['analysis_details']['pe_analysis'] = pe_analysis
                all_risk_factors.extend([RiskFactor(**rf) for rf in pe_analysis.get('risk_factors', [])])

        # Document analysis
        elif any(doc_type in file_type.lower() for doc_type in ['word', 'excel', 'powerpoint', 'pdf', 'composite document']):
            doc_risks = analyze_document(filepath, file_type)
            all_risk_factors.extend(doc_risks)
        
        # Script file analysis
        elif any(ext in filename.lower() for ext in ['.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse', '.bat', '.cmd']):
            script_risks = analyze_script_file(filepath, file_type, filename)
            all_risk_factors.extend(script_risks)
        
        # Archive file analysis
        elif any(archive_type in file_type.lower() for archive_type in ['zip', 'rar', '7-zip', 'gzip', 'tar', 'compressed']):
            archive_risks = analyze_archive_file(filepath, file_type)
            all_risk_factors.extend(archive_risks)

        # Calculate overall verdict and risk level
        high_risks = sum(1 for rf in all_risk_factors if rf.severity == 'high')
        medium_risks = sum(1 for rf in all_risk_factors if rf.severity == 'medium')
        low_risks = sum(1 for rf in all_risk_factors if rf.severity == 'low')

        # More nuanced risk assessment
        if high_risks >= 3:
            results['verdict'] = 'Malicious'
            results['risk_level'] = 'critical'
        elif high_risks > 0:
            results['verdict'] = 'Malicious'
            results['risk_level'] = 'high'
        elif medium_risks >= 3:
            results['verdict'] = 'Suspicious'
            results['risk_level'] = 'high'
        elif medium_risks > 0:
            results['verdict'] = 'Suspicious'
            results['risk_level'] = 'medium'
        elif low_risks > 0:
            results['verdict'] = 'Potentially Suspicious'
            results['risk_level'] = 'low'

        # Convert risk factors to dictionaries for JSON serialization
        results['risk_factors'] = [vars(rf) for rf in all_risk_factors]

        return results

    except Exception as e:
        logger.error(f"Error in file analysis: {str(e)}")
        results['verdict'] = 'Error'
        results['risk_level'] = 'unknown'
        results['risk_factors'].append({
            'name': 'Analysis Error',
            'description': str(e),
            'severity': 'error',
            'category': 'System Error'
        })
        return results