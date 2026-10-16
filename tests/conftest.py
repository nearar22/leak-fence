import os
from gltest.direct import sdk_loader

_real_unlink = os.unlink


def _windows_safe_unlink(path, *args, **kwargs):
    try:
        return _real_unlink(path, *args, **kwargs)
    except PermissionError:
        return None


os.unlink = _windows_safe_unlink
_real_parse = sdk_loader.parse_contract_header


def _parse_with_bundled_runner(path):
    dependencies = _real_parse(path)
    if dependencies.get("py-genlayer") == "5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng":
        dependencies["py-genlayer"] = "babwp9t37jw9g4j2bccgn14g6x7x9s1f7dsmh7emvz735pz4zxa0"
    return dependencies


sdk_loader.parse_contract_header = _parse_with_bundled_runner

