


## Useful Commands

- Access the database
`sudo -u postgres psql -d scandb`

- Remove all entries and reset sequences for hosts table
`TRUNCATE hosts RESTART IDENTITY;`