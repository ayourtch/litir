= My exploration into ActivityPub

This code doesn't do much useful yet.

= Installation

Install rust, clone this repo, then make a vhost that points out to 127.0.0.1:4000

Then configure https:

```
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your.domain.name
```

the domain x25.me is hardcoded so far in the code, while I am toying around with it all.

= Credits

Thanks a lot to Darius Kazemi, whose guide at https://tinysubversions.com/notes/reading-activitypub/ - as well as his code, has inspired me to try out this experiment.



