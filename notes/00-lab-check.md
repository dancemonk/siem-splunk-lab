# Splunk lab check: BOTS v1

Date: 2026-11-10.

## What I checked and why

I always chec the tool and the data I have before I start searchin. Then I can trust my results, also when a search returns nothing.

## Commands and SPL I want to remember

- 'ss -tln': shows which TCP ports are listening on this machine, and on which address. '127.0.0.1' means only this machine can connect; '0.0.0.0' or '*' means any device on the network. I used it to check that Splunk is not open to my network.
