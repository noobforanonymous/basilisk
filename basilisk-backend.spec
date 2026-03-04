# -*- mode: python ; coding: utf-8 -*-
# Basilisk v1.0.3 — PyInstaller spec for the desktop backend sidecar binary.
# Bundles the full backend: core engine, attack modules, evolution engine,
# providers, recon, payloads, reports, and all dependencies.
#
# Usage:
#   cd /path/to/basilisk            (project root, not desktop/)
#   source venv/bin/activate
#   pip install pyinstaller
#   pyinstaller basilisk-backend.spec
#
# The output binary will be at: dist/basilisk-backend
# Copy it to: desktop/bin/basilisk-backend
#
# For Windows cross-compile (must be run on Windows):
#   python -m PyInstaller basilisk-backend.spec
#   → Output: dist\basilisk-backend.exe

from PyInstaller.utils.hooks import collect_data_files

all_datas = collect_data_files('certifi') + [
    # Payload YAML database
    ('basilisk/payloads', 'basilisk/payloads'),
    # Jinja2 report templates
    ('basilisk/report/templates', 'basilisk/report/templates'),
    # Native libraries (C/Go)
    ('basilisk/native_libs', 'basilisk/native_libs'),
]

a = Analysis(
    ['basilisk/desktop_backend.py'],
    pathex=['.'],
    binaries=[],
    datas=all_datas,
    hiddenimports=[
        # ── Core Basilisk modules ──
        'basilisk',
        'basilisk.__init__',
        'basilisk.__main__',
        'basilisk.desktop_backend',
        'basilisk.native_bridge',

        # ── Core Engine ──
        'basilisk.core',
        'basilisk.core.config',
        'basilisk.core.database',
        'basilisk.core.finding',
        'basilisk.core.profile',
        'basilisk.core.session',
        'basilisk.core.refusal',

        # ── New v1.0.3 Modules ──
        'basilisk.core.audit',
        'basilisk.differential',
        'basilisk.posture',

        # ── Attack Modules (8 categories, 29 sub-modules) ──
        'basilisk.attacks',
        'basilisk.attacks.base',
        # Injection
        'basilisk.attacks.injection',
        'basilisk.attacks.injection.direct',
        'basilisk.attacks.injection.indirect',
        'basilisk.attacks.injection.multilingual',
        'basilisk.attacks.injection.encoding',
        'basilisk.attacks.injection.split',
        # Extraction
        'basilisk.attacks.extraction',
        'basilisk.attacks.extraction.role_confusion',
        'basilisk.attacks.extraction.translation',
        'basilisk.attacks.extraction.simulation',
        'basilisk.attacks.extraction.gradient_walk',
        # Exfiltration
        'basilisk.attacks.exfil',
        'basilisk.attacks.exfil.training_data',
        'basilisk.attacks.exfil.rag_data',
        'basilisk.attacks.exfil.tool_schema',
        # Tool Abuse
        'basilisk.attacks.toolabuse',
        'basilisk.attacks.toolabuse.ssrf',
        'basilisk.attacks.toolabuse.sqli',
        'basilisk.attacks.toolabuse.command_injection',
        'basilisk.attacks.toolabuse.chained',
        # Guardrail Bypass
        'basilisk.attacks.guardrails',
        'basilisk.attacks.guardrails.roleplay',
        'basilisk.attacks.guardrails.encoding_bypass',
        'basilisk.attacks.guardrails.logic_trap',
        'basilisk.attacks.guardrails.systematic',
        # DoS
        'basilisk.attacks.dos',
        'basilisk.attacks.dos.token_exhaustion',
        'basilisk.attacks.dos.context_bomb',
        'basilisk.attacks.dos.loop_trigger',
        # Multi-turn
        'basilisk.attacks.multiturn',
        'basilisk.attacks.multiturn.escalation',
        'basilisk.attacks.multiturn.persona_lock',
        'basilisk.attacks.multiturn.memory_manipulation',
        # RAG
        'basilisk.attacks.rag',
        'basilisk.attacks.rag.poisoning',
        'basilisk.attacks.rag.document_injection',
        'basilisk.attacks.rag.knowledge_enum',

        # ── Evolution Engine (SPE-NL) ──
        'basilisk.evolution',
        'basilisk.evolution.engine',
        'basilisk.evolution.operators',
        'basilisk.evolution.fitness',
        'basilisk.evolution.population',
        'basilisk.evolution.crossover',

        # ── Provider Adapters ──
        'basilisk.providers',
        'basilisk.providers.base',
        'basilisk.providers.litellm_adapter',
        'basilisk.providers.custom_http',
        'basilisk.providers.websocket',

        # ── Recon ──
        'basilisk.recon',
        'basilisk.recon.fingerprint',
        'basilisk.recon.guardrails',
        'basilisk.recon.tools',
        'basilisk.recon.context',
        'basilisk.recon.rag',

        # ── Reporting ──
        'basilisk.report',
        'basilisk.report.generator',
        'basilisk.report.html',
        'basilisk.report.sarif',
        'basilisk.report.pdf',

        # ── CLI (for potential embedded usage) ──
        'basilisk.cli',
        # ── CLI (for potential embedded usage) ──
        'basilisk.cli',
        'basilisk.cli.main',
        'basilisk.cli.scan',
        'basilisk.cli.utils',
        'basilisk.cli.recon',

        # ── LiteLLM (universal provider — must include submodules) ──
        'litellm',
        'litellm.main',
        'litellm.utils',

        # ── Third-party libraries PyInstaller may miss ──
        'uvicorn',
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'fastapi',
        'fastapi.middleware',
        'fastapi.middleware.cors',
        'starlette',
        'starlette.routing',
        'starlette.middleware',
        'starlette.middleware.cors',
        'starlette.responses',
        'websockets',
        'websockets.legacy',
        'websockets.legacy.client',
        'aiohttp',
        'yaml',
        'sqlite3',
        'click',
        'rich',
        'rich.console',
        'rich.table',
        'rich.panel',
        'rich.progress',
        'jinja2',

        # ── pkg_resources / setuptools chain (jaraco crash fix) ──
        'pkg_resources',
        'jaraco',
        'jaraco.text',
        'jaraco.functools',
        'jaraco.context',
        'importlib_metadata',
        'setuptools',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Heavy dev/test deps not needed at runtime
        'tkinter',
        'matplotlib',
        'pandas',
        'scipy',
        'pytest',
        'pyinstaller',
        'pip',
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='basilisk-backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
