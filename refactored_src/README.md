

## For Testing
- run `monitoring/psql_monitoring.py` to monitor psql connections
- run `monitoring/rmq_monitoring.py` to monitor RabbitMQ connections


## Useful Commands

- Run the application (with .venv enabled!)
    - IP Scan / Host Discovery: `python ./start_application ip`
    - Port Scan: `python ./start_application port`

- Access the database
`sudo -u postgres psql -d scandb`

- Query to check amount of active connections
`select * from pg_stat_activity where pg_stat_activity.usename = 'scanner';`

- Remove all entries and reset sequence for
    - ALL `TRUNCATE hosts, ports, summary RESTART IDENTITY;`
    - Only hosts `TRUNCATE hosts RESTART IDENTITY;`
    - Only ports `TRUNCATE ports RESTART IDENTITY;`
    - Only summary `TRUNCATE summary RESTART IDENTITY;`


## Notes
- When I tested the application, I noticed that the fail_queue takes in the batch by default. 