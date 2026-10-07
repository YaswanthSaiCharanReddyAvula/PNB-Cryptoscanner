"""
QuantumShield — CycloneDX 1.6 Exporter

Generates a fully compliant CycloneDX 1.6 Software Bill of Materials (SBOM)
from a CanonicalEstate.
"""

from typing import Dict
from datetime import datetime, timezone
import uuid

from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.vulnerability import Vulnerability
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.model.bom import Tool, OrganizationalEntity

from app.scanner.convergence.aggregation import CanonicalEstate
from app.scanner.convergence.cyclonedx.component_mapper import (
    map_asset_to_component,
    _map_asset_type_to_cdx_type,
)
from app.scanner.convergence.cyclonedx.crypto_mapper import enrich_component_with_crypto
from app.scanner.convergence.cyclonedx.vulnerability_mapper import map_finding_to_vulnerability


class CycloneDXExporter:
    def __init__(self, estate: CanonicalEstate):
        self.estate = estate
        self.bom = Bom()
        self.bom.metadata = self._build_metadata()
        self.components_by_id: Dict[str, Component] = {}

    def _build_metadata(self) -> BomMetaData:
        metadata = BomMetaData(
            timestamp=datetime.now(timezone.utc),
            tools=[Tool(vendor="ECDAT", name="QuantumShield", version="2.0.0")]
        )
        # Root component representing the target estate
        root_component = Component(
            name=self.estate.target,
            type=ComponentType.APPLICATION,
            bom_ref="root-estate"
        )
        metadata.component = root_component
        return metadata

    def _process_assets(self, asset_list):
        for asset in asset_list:
            if asset.asset_id in self.components_by_id:
                continue
                
            component = map_asset_to_component(asset)
            enrich_component_with_crypto(component, asset)
            
            self.components_by_id[asset.asset_id] = component
            self.bom.components.add(component)

    def generate(self) -> str:
        """
        Builds the BOM and serializes it to CycloneDX 1.6 JSON.
        """
        # Process all asset categories
        self._process_assets(self.estate.assets.hosts)
        self._process_assets(self.estate.assets.services)
        self._process_assets(self.estate.assets.technologies)
        self._process_assets(self.estate.assets.packages)
        self._process_assets(self.estate.assets.containers)
        self._process_assets(self.estate.assets.certificates)
        self._process_assets(self.estate.assets.keys)
        self._process_assets(self.estate.assets.algorithms)
        self._process_assets(self.estate.assets.cloud_resources)
        self._process_assets(self.estate.assets.protocols)
        self._process_assets(self.estate.assets.other)

        # Build relationships (Dependencies in CycloneDX)
        # CycloneDX represents relationships mainly through dependencies graph
        for asset_list in self.estate.assets.__dict__.values():
            for asset in asset_list:
                comp = self.components_by_id.get(asset.asset_id)
                if not comp:
                    continue
                    
                # Link asset relationships to CycloneDX dependencies
                for rel in asset.relationships:
                    target_comp = self.components_by_id.get(rel.target_id)
                    if target_comp:
                        # Register dependency in BOM
                        self.bom.register_dependency(comp, [target_comp])
                        
        # Map Findings to Vulnerabilities
        for finding in self.estate.findings:
            if finding.finding_type == "vulnerability" or finding.severity.name != "UNKNOWN":
                vuln = map_finding_to_vulnerability(finding)
                
                # Affects mapping
                for asset_ref in finding.asset_refs:
                    if asset_ref in self.components_by_id:
                        vuln.affects.add(self.components_by_id[asset_ref].bom_ref)
                        
                self.bom.vulnerabilities.add(vuln)
                
        # Link all top-level components to the root component if they don't have parents
        # (Simplified: we link everything directly under root for estate scanning if not nested)
        if self.bom.metadata and self.bom.metadata.component:
            self.bom.register_dependency(self.bom.metadata.component, list(self.bom.components))

        # Serialize
        outputter = JsonV1Dot6(self.bom)
        return outputter.output_as_string()
