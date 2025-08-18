# DEV DOCS

Development documentation, how to run etc can be found here.


## Run a Scan

1. First, enable .venv!
2. Go to `config/scan_config.py` and change the `SCAN_TYPE` to **ip** for running host discovery only or **port** for port scan.
3. Run it in terminal or using `tmux`

### 1. Enable Venv

```bash
cd scanner
source .venv/bin/activate
```

### 3.A Run in terminal 

```bash
python start_application.py
```

### 3.B Run as background job using tmux

You can run the scanner by detaching it from current terminal session (so it doesn't exit when you close the terminal) by using `tmux` :

First install it with `sudo apt update && sudo apt install tmux -y`.

#### Using tmux

**Start a session and run the scan:**

```bash
tmux new -s volva # now we are inside tmux (status bar at the bottom)

# run the scan
cd scanner
source .venv/bin/activate
python start_application.py
```

**Detach from the session:**

When you have started the scan, you can detach and leave it running in the background by pressing `Ctrl` + `B`, and then `D`.

**Re-attach to the session:**

```bash
tmux attach -t volva
```

**Other useful commands:**

```bash
tmux ls # list sessions
tmux kill-session -t scanner # stop the session (if you need to force close)
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
