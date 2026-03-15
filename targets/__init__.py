"""
ShieldKit Target Resolution
----------------------------
Normalises any input form (uploaded file, public/private URL, S3, git repo,
container ref, local path) into a path/ref each scanner already expects.
"""

from .resolver import TargetResolver, LocalTarget

__all__ = ["TargetResolver", "LocalTarget"]
