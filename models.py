import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class Community:
    name: Optional[str] = field(default=None)

    def __str__(self):
        return f"Community [name={self.name}]"
    

@dataclass
class Domain:
    name: Optional[str] = field(default=None)
    community: Optional[Community] = field(default=None)

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, skipkeys=True)

    def __str__(self):
        return f"Domain [name={self.name}, community={self.community}]"
    

@dataclass
class Identifier:
    name: Optional[str] = field(default=None)
    domain: Optional['Domain'] = field(default=None)
    community: Optional['Community'] = field(default=None)

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, skipkeys=True)

    def __str__(self):
        return f"Identifier [name={self.name}, domain={self.domain}, community={self.community}]"


@dataclass
class Type:
    name: Optional[str] = field(default=None)

    def __str__(self):
        return f"Type [name={self.name}]"    


@dataclass
class Entry:
    resourceType: Optional[str] = None
    identifier: Optional['Identifier'] = None
    type: Optional['Type'] = None
    displayName: Optional[str] = None
    attributes: Dict[str, List[str]] = field(default_factory=dict)
    relations: Dict[str, List['Identifier']] = field(default_factory=dict)

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, skipkeys=True)

    def __str__(self) -> str:
        return f"Entry [resourceType={self.resourceType}, identifier={self.identifier}, type={self.type}, displayName={self.displayName}, attributes={self.attributes}, relations={self.relations}]"
    

@dataclass
class Step:
    step_number: Optional[int] = field(default=None, metadata={"json": "stepNumber"})
    resource_location: Optional[str] = field(default=None, metadata={"json": "resourceLocation"})
    file_name: Optional[str] = field(default=None, metadata={"json": "fileName"})
    part_number: Optional[int] = field(default=None, metadata={"json": "partNumber"})

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, skipkeys=True)

    def __str__(self):
        return f"Step [stepNumber={self.step_number}, resourceLocation={self.resource_location}, fileName={self.file_name}, partNumber={self.part_number}]"