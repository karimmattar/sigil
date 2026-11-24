"""Infrastructure layer: adapters that implement the domain ports.

* :mod:`.pkcs11` — python-pkcs11 driver access (TokenGateway)
* :mod:`.pyhanko_engine` — pyHanko PDF/CMS signing (PdfSigningEngine, CmsSigningEngine)
* :mod:`.logging_setup` — logging + audit trail (AuditLog)
* :mod:`.config`, :mod:`.paths` — settings and per-OS locations
"""
