# My exploration into ActivityPub

This code doesn't do much useful yet. It merely attempts to send the correct responses
to the follow and unfollow requests, without doing a lot on its side.

The verification of the incoming messages does not take the date into account.

# Installation

Install rust, clone this repo, then make a vhost that points out to 127.0.0.1:4000

Then configure https:

```
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your.domain.name
```
# Running

```
export LITIR_FQDN=your.domain.name
cargo run -- -d sqlite://./test.sqlite3 create-actor --username testuser --name "Test User" --summary "This is just a test account"
cargo run -- -d sqlite://./test.sqlite3 web-service
```

# Credits

Thanks a lot to Darius Kazemi, whose guide at https://tinysubversions.com/notes/reading-activitypub/ - as well as his code, has inspired me to try out this experiment.



