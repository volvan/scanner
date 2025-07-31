# DEV DOCS

## For Monitoring (testing)
- run `monitoring/psql_monitoring.py` to monitor psql connections
- run `monitoring/rmq_monitoring.py` to monitor RabbitMQ connections

---

## Run the application

First, enable .venv!

```bash
cd scanner
source .venv/bin/activate
```

### Run host discovery: 
```bash
python refactored_src/start_application.py ip
```

### Run port scan:

```bash
python refactored_src/start_application.py port
```

---

## Access the database

```bash
sudo -u postgres psql -d scandb
```

### Query to check amount of active connections

```sql
select * from pg_stat_activity where pg_stat_activity.usename = 'scanner';
```

### Remove all entries and reset sequence for..

1. All 
```sql
TRUNCATE hosts, ports, summary RESTART IDENTITY;
```

2. Only hosts
```sql
TRUNCATE hosts RESTART IDENTITY;
```

3. Only ports
```sql
TRUNCATE ports RESTART IDENTITY;
```

4. Only summary 
```sql
TRUNCATE summary RESTART IDENTITY;
```

---

## Notes

? When I tested the application, I noticed that the fail_queue takes in the batch by default. # TODO[Franz]

