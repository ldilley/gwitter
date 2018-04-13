gwitter
=======
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

GitHub to Twitter hook glue

Gwitter is primarily being written for use with the [SEGS Project](https://github.com/Segs/Segs) for Twitter
and Discord notifications. As such, only pull request/merge and release events are currently handled considering
the needs of the aforementioned project. You will need to manually handle other specific event types that you want
posted to Twitter as a result. Support for more events will likely be added for posterity at some point. For a
list of available events supported by the GitHub API, please see the following:

https://developer.github.com/webhooks/#events

https://developer.github.com/v3/activity/events/types/

Gwitter requires the use of Twitter consumer and access tokens for authentication and authorization. These can
be procured after creating a Twitter application at: https://apps.twitter.com/

For added security, you can optionally:
* Permit traffic on your firewall for just the hook networks referenced here: https://api.github.com/meta

* Generate a GitHub hook secret for validation using:

`ruby -rsecurerandom -e 'puts SecureRandom.hex(20)'`

* Make use of SSL certificates which can be generated using Let's Encrypt or another CA. You may also generate
self-signed certificates using:

`openssl req -x509 -nodes -newkey rsa:2048 -keyout server.key -out server.crt -days 365`

Note: If you are utilizing self-signed certificates, you must disable SSL verification for the GitHub hook.

Gwitter has the following requirements:

Ruby (including [JRuby](http://jruby.org/)) >=2.2

[Sinatra Gem](https://github.com/sinatra/sinatra)

[Twitter Gem](https://github.com/sferik/twitter)
