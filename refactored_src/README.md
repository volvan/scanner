


## Useful Commands

- Access the database
`sudo -u postgres psql -d scandb`

- Remove all entries and reset sequences for hosts table
`TRUNCATE hosts RESTART IDENTITY;`


## Notes
- When I tested the application, I noticed that the fail_queue takes in the batch by default. 