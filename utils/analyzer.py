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
        'VirtualAlloc': ('Memory allocation', 'Could be used for shellcode injection'),
        'WriteProcessMemory': ('Process manipulation', 'Indicates potential process tampering'),
        'CreateRemoteThread': ('Process manipulation', 'Common in code injection techniques'),
        'LoadLibrary': ('Dynamic loading', 'May load malicious DLLs'),
        'SetWindowsHookEx': ('System hooks', 'Could be used for keylogging'),
        'WSASocket': ('Network activity', 'Raw socket operations'),
        'InternetOpen': ('Network activity', 'Internet connectivity'),
        'CryptEncrypt': ('Cryptographic', 'Data encryption capability'),
        'RegCreateKey': ('Registry manipulation', 'Registry modifications')
    }

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                imp_name = imp.name.decode().lower()
                for sus_import, (category, desc) in suspicious_imports.items():
                    if sus_import.lower() in imp_name:
                        risk_factors.append(RiskFactor(
                            name=f"Suspicious Import: {imp_name}",
                            description=desc,
                            severity="medium" if "crypto" in imp_name.lower() else "high",
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

def analyze_pe_file(filepath):
    try:
        pe = pefile.PE(filepath)
        risk_factors = []

        # Collect risk factors from different analyses
        risk_factors.extend(analyze_pe_imports(pe))
        risk_factors.extend(analyze_pe_sections(pe))
        risk_factors.extend(analyze_pe_characteristics(pe))

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
    if "OLE" in file_type:
        risk_factors.append(RiskFactor(
            name="Embedded Objects",
            description="Document contains embedded objects which could be malicious",
            severity="medium",
            category="Document Features"
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
        if 'PE32' in file_type:
            pe_analysis = analyze_pe_file(filepath)
            if pe_analysis:
                results['analysis_details']['pe_analysis'] = pe_analysis
                all_risk_factors.extend([RiskFactor(**rf) for rf in pe_analysis.get('risk_factors', [])])

        # Document analysis
        elif any(doc_type in file_type.lower() for doc_type in ['word', 'excel', 'powerpoint', 'pdf']):
            doc_risks = analyze_document(filepath, file_type)
            all_risk_factors.extend(doc_risks)

        # Calculate overall verdict and risk level
        high_risks = sum(1 for rf in all_risk_factors if rf.severity == 'high')
        medium_risks = sum(1 for rf in all_risk_factors if rf.severity == 'medium')

        if high_risks > 0:
            results['verdict'] = 'Malicious'
            results['risk_level'] = 'high'
        elif medium_risks > 0:
            results['verdict'] = 'Suspicious'
            results['risk_level'] = 'medium'

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