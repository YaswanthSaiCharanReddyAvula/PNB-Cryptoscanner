"""
QuantumShield — CycloneDX Validator

Validates generated CycloneDX 1.6 JSON against the official schema and applies
custom semantic rules.
"""

import json
from typing import Dict, Any, Tuple, List
import jsonschema


# Basic subset of CycloneDX 1.6 schema for runtime validation if official schema file isn't loaded
# In a real environment, you'd load the official JSON schema from https://cyclonedx.org/schema/bom-1.6b.schema.json
CDX_1_6_BASIC_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["bomFormat", "specVersion", "version"],
    "properties": {
        "bomFormat": {"type": "string", "enum": ["CycloneDX"]},
        "specVersion": {"type": "string", "enum": ["1.6"]},
        "version": {"type": "integer", "minimum": 1}
    }
}


def validate_cyclonedx(json_str: str, schema_dict: Dict = CDX_1_6_BASIC_SCHEMA) -> Tuple[bool, List[str]]:
    """
    Validates a CycloneDX JSON string against the schema and performs semantic checks.
    """
    errors = []
    try:
        parsed = json.loads(json_str)
    except json.JSONDecodeError as e:
        return False, [f"Invalid JSON: {e}"]
        
    try:
        jsonschema.validate(instance=parsed, schema=schema_dict)
    except jsonschema.exceptions.ValidationError as e:
        errors.append(f"Schema Validation Error: {e.message}")
        
    # Semantic validations
    bom_refs = set()
    
    # Check for unique bom-refs
    def check_components(components_list):
        for comp in components_list:
            ref = comp.get("bom-ref")
            if ref:
                if ref in bom_refs:
                    errors.append(f"Duplicate bom-ref found: {ref}")
                bom_refs.add(ref)
            check_components(comp.get("components", []))
            
    check_components(parsed.get("components", []))
    if "metadata" in parsed and "component" in parsed["metadata"]:
        check_components([parsed["metadata"]["component"]])
        
    # Check that all dependencies references valid bom-refs
    for dep in parsed.get("dependencies", []):
        ref = dep.get("ref")
        if ref and ref not in bom_refs:
            errors.append(f"Dependency references unknown bom-ref: {ref}")
        for depends_on in dep.get("dependsOn", []):
            if depends_on not in bom_refs:
                errors.append(f"Dependency dependsOn unknown bom-ref: {depends_on}")
                
    return len(errors) == 0, errors
