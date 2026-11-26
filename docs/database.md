# Access database setup

Access uses PostgreSQL 16, Flyway 12.11.0 and the PostgreSQL JDBC driver 42.7.14. It expects an `access` schema owned by the `sotto_access` role in the `sotto_access` database. Application startup runs the checked-in Flyway migrations with that role. A failed migration stops startup.

## Provision the database

Run the provisioning script once as a PostgreSQL administrator connected to the maintenance database. Supply the chosen Access password through `ACCESS_DB_PASSWORD` in the administrator's shell or secret runner.

```sh
psql -X -d postgres -f scripts/provision-access.sql
```

The script creates the dedicated login, database and schema. The login can connect to the Access database and create objects in its own schema. It has no cluster administration privileges. Configure the application with `SPRING_DATASOURCE_URL`, `SPRING_DATASOURCE_USERNAME` and `SPRING_DATASOURCE_PASSWORD`.

## Share a PostgreSQL server with Sotto

PostgreSQL grants database connection and temporary-schema privileges to `PUBLIC` by default. On a shared server, grant the required privileges to the existing Sotto roles explicitly before revoking those default privileges on the Sotto database. For the standard `sotto` database and role, an administrator can run the following.

```sql
GRANT CONNECT, TEMPORARY ON DATABASE sotto TO sotto;
REVOKE CONNECT, TEMPORARY ON DATABASE sotto FROM PUBLIC;
```

Check the names and any additional legitimate roles on your server first. The integration test uses two databases on one PostgreSQL server and verifies that the Access role can migrate its own schema and receives a permission error when it tries to connect to Sotto.
