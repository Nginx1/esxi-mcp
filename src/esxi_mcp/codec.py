"""JSON <-> declared pyVmomi types; never evaluate arbitrary Python."""
from __future__ import annotations
import base64
import datetime
import math
import re
from typing import Any
from pyVmomi import VmomiSupport as V
from mcp.server.fastmcp.exceptions import ToolError

SECRET_FIELD = re.compile(r'password|passwd|^pwd$|secret|token|ticket|cookie|license.?key|private.?key|session.?key|session.?id|^source_url$|^transfer_url$|^keyData$|^keyMaterial$', re.I)

def secret_field(name):
    return bool(SECRET_FIELD.search(str(name)))

def scrub(value):
    if isinstance(value, dict):
        option_secret = secret_field(value.get('key', ''))
        return {key: '[BASE64 PAYLOAD: ' + str(len(item)) + ' chars]' if key == 'data_base64' and isinstance(item, str)
                else '[REDACTED]' if secret_field(key) or (option_secret and key == 'value')
                else scrub(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(item) for item in value]
    return value

def secret_values(value):
    if isinstance(value, dict):
        values = []
        for key, item in value.items():
            if secret_field(key) and isinstance(item, str) and item:
                values.append(item)
            values.extend(secret_values(item))
        return values
    if isinstance(value, (list, tuple)):
        return [secret for item in value for secret in secret_values(item)]
    return []

def resolve_type(name):
    if not isinstance(name, str) or not name.startswith(('vim.', 'vmodl.')):
        raise ToolError('Type must be a declared vim.* or vmodl.* SDK type')
    try:
        return V.GetVmodlType(name)
    except Exception:
        raise ToolError('Unknown SDK type: ' + name) from None

def reference(value, stub):
    if not isinstance(value, dict) or set(value) != {'_type', '_moId'}:
        raise ToolError('Managed reference requires exactly {_type, _moId}')
    cls = resolve_type(value['_type'])
    if not issubclass(cls, V.ManagedObject):
        raise ToolError('Reference type must be a ManagedObject')
    if not isinstance(value['_moId'], str) or not value['_moId'] or len(value['_moId']) > 256:
        raise ToolError('Invalid managed object ID')
    return cls(value['_moId'], stub)

def decode(value, expected, stub, depth=0):
    if depth > 20:
        raise ToolError('Input nesting exceeds 20 levels')
    if value is None:
        return None
    if issubclass(expected, V.Array):
        if not isinstance(value, list) or len(value) > 10000:
            raise ToolError('Expected bounded JSON array: ' + expected.__name__)
        return expected([decode(item, expected.Item, stub, depth + 1) for item in value])
    if issubclass(expected, V.ManagedObject):
        obj = reference(value, stub)
        if not isinstance(obj, expected):
            raise ToolError('Managed reference is not a ' + expected.__name__)
        return obj
    if issubclass(expected, V.DataObject):
        if not isinstance(value, dict):
            raise ToolError('Expected JSON object: ' + expected.__name__)
        cls = resolve_type(value['_type']) if '_type' in value else expected
        if not issubclass(cls, expected):
            raise ToolError('Data subtype is not a ' + expected.__name__)
        properties = {prop.name: prop for prop in cls._GetPropertyList()}
        unknown = set(value) - set(properties) - {'_type'}
        if unknown:
            raise ToolError('Unknown data properties: ' + ', '.join(sorted(unknown)))
        obj = cls()
        for key, item in value.items():
            if key != '_type':
                setattr(obj, key, decode(item, properties[key].type, stub, depth + 1))
        return obj
    if expected is object:
        if isinstance(value, dict) and '_type' in value:
            return decode(value, resolve_type(value['_type']), stub, depth + 1)
        if isinstance(value, (str, bool, int, float)):
            return value
        raise ToolError('AnyType needs a scalar or a typed {_type, ...} object')
    if issubclass(expected, bool):
        if not isinstance(value, bool):
            raise ToolError('Expected a JSON boolean')
        return value
    if issubclass(expected, int):
        if not isinstance(value, int) or isinstance(value, bool):
            raise ToolError('Expected a JSON integer')
        return expected(value)
    if issubclass(expected, float):
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
            raise ToolError('Expected a finite JSON number')
        return expected(value)
    if issubclass(expected, str):
        if not isinstance(value, str):
            raise ToolError('Expected a JSON string')
        if issubclass(expected, V.Enum) and value not in expected.values:
            raise ToolError('Invalid enum value for ' + expected.__name__)
        return expected(value)
    if expected is datetime.datetime:
        return datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if expected is V.binary:
        return V.binary(base64.b64decode(value, validate=True))
    raise ToolError('Unsupported input type: ' + expected.__name__)

def encode(value, depth=4, max_items=100):
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, V.ManagedObject):
        return {'_type': type(value).__name__, '_moId': str(value._moId)}
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return base64.b64encode(value).decode('ascii')
    if depth <= 0:
        return {'_truncated': True, '_type': type(value).__name__}
    if isinstance(value, V.DataObject):
        result = {'_type': type(value).__name__}
        option_secret = secret_field(getattr(value, 'key', ''))
        session = type(value).__name__ == 'vim.UserSession'
        for prop in value._GetPropertyList():
            item = getattr(value, prop.name, None)
            if item is not None:
                result[prop.name] = ('[REDACTED]' if secret_field(prop.name)
                                    or (option_secret and prop.name == 'value')
                                    or (session and prop.name == 'key')
                                    else encode(item, depth - 1, max_items))
        return result
    if isinstance(value, (list, tuple)):
        items = [encode(item, depth - 1, max_items) for item in value[:max_items]]
        if len(value) > max_items:
            items.append({'_truncated': True, 'remaining': len(value) - max_items})
        return items
    if isinstance(value, dict):
        return scrub({str(key): encode(item, depth - 1, max_items) for key, item in value.items()})
    return str(value)

def vm_references(value):
    from pyVmomi import vim
    if isinstance(value, vim.VirtualMachine):
        yield value
    elif isinstance(value, V.DataObject):
        for prop in value._GetPropertyList():
            yield from vm_references(getattr(value, prop.name, None))
    elif isinstance(value, dict):
        for item in value.values():
            yield from vm_references(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from vm_references(item)

def type_schema(cls, depth=2):
    result = {'type': cls.__name__}
    if issubclass(cls, V.Array):
        result['items'] = type_schema(cls.Item, max(0, depth - 1))
    elif issubclass(cls, V.Enum):
        result['values'] = list(cls.values)
    elif issubclass(cls, V.ManagedObject):
        result['json'] = {'_type': cls.__name__, '_moId': 'ID_FROM_DISCOVERY'}
    elif issubclass(cls, V.DataObject) and depth > 0:
        result['properties'] = {prop.name: {**type_schema(prop.type, depth - 1),
                                           'optional': bool(prop.flags & V.F_OPTIONAL)}
                                for prop in cls._GetPropertyList()}
    return result
