from enum import Enum, auto


class TrustLevel(str, Enum):
    """
    How much an agent tool trusts the data it receives as input.

    TRUSTED  - input comes from the developer / system prompt only (safe)
    UNTRUSTED - input comes from the end user (semi-controlled)
    EXTERNAL  - input comes from outside the system boundary entirely:
                web pages, emails, uploaded files, database records, API
                responses from third parties.  This is the attack surface.
    """
    TRUSTED   = "trusted"
    UNTRUSTED = "untrusted"
    EXTERNAL  = "external"


class SinkType(str, Enum):
    """
    Categories of sensitive actions a tool can perform.
    A tool that writes to any of these is a potential exfiltration
    or damage vector when reached via an untrusted input chain.
    """
    FILE_WRITE  = "file_write"    # writes / overwrites files on disk
    CODE_EXEC   = "code_exec"     # runs arbitrary code (subprocess, eval, etc.)
    EMAIL_SEND  = "email_send"    # sends an outbound email
    API_CALL    = "api_call"      # calls an external HTTP endpoint
    DB_WRITE    = "db_write"      # inserts / updates a database
    SHELL       = "shell"         # runs shell commands
    MEMORY_WRITE = "memory_write" # writes to agent long-term memory store


class Severity(str, Enum):
    """
    CVSS-inspired severity for a confirmed exploit path.
    Assigned by the executor based on sink type and path length.
    """
    CRITICAL = "critical"   # CODE_EXEC or SHELL reached via EXTERNAL source
    HIGH     = "high"       # FILE_WRITE, EMAIL_SEND, DB_WRITE via EXTERNAL
    MEDIUM   = "medium"     # API_CALL or MEMORY_WRITE via EXTERNAL
    LOW      = "low"        # any sink reached via UNTRUSTED (not EXTERNAL)
    INFO     = "info"       # path exists but no dangerous sink reached
