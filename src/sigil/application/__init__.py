"""Application layer: use cases that orchestrate domain policies and ports.

Framework-free: no FastAPI, python-pkcs11 or pyHanko imports. Services are plain,
synchronous classes; the API layer decides how to run them (worker threads).
"""
