# Rita with Sessions

This repo is an example of using [Rita](https://github.com/synadia-labs/rita) with 
[SCS](https://github.com/alexedwards/scs).


## Requirements

- NATS
- [task](https://taskfile.dev)
- [air](https://github.com/air-verse/air) (if using `task`)

## Getting started

The following walks through the full process of registering a user, logging in,
and logging out. It also has a demo of a per-user login history projection.

Each side effect is a durable consumer so we do not replay then when the log is replayed.

## 1. Start the server

```bash
task dev
```

Expected output:

```
level=INFO msg=listening addr=:9998
```

## 2. Register a user

```bash
curl -v -c jar.txt -X POST localhost:9998/register \
  --data-urlencode 'email=dan@example.com' \
  --data-urlencode 'password=secret'
```

Expected: `201 Created` with body `registered - you can now log in`

## 3. Inspect the event store

```bash
task nats -- stream ls
task nats -- stream view ES_auth
```

Expected: the `ES_auth` stream contains a `UserRegistered` event in rita's format. No separate KV projection buckets — the read model lives in-memory via `Model.View()`. (Rita prefixes stream names with `ES_`, so the event store named `auth` lives in stream `ES_auth`.)

## 4. Log in

```bash
curl -v -c jar.txt -b jar.txt localhost:9998/login \
  --data-urlencode 'email=dan@example.com' \
  --data-urlencode 'password=secret' -L
```

Expected: `303 See Other` redirect to `/dashboard`, then `200 OK` with `welcome dan@example.com (id: <nuid>)`.

## 5. Access the dashboard

```bash
curl -v -b jar.txt localhost:9998/dashboard
```

Expected: `200 OK` with `welcome dan@example.com`.

## 6. Check the session in NATS

```bash
task nats -- kv ls sessions
```

Expected: one session key (the SCS token from the cookie).

We can view the session value with:

``` 
task nats -- kv get sessions $key --raw | strings
```

## 7. Log out

```bash
curl -v -c jar.txt -b jar.txt -X POST localhost:9998/logout
```

Expected: `303 See Other` redirect to `/login`.

## 8. Confirm session is destroyed

```bash
curl -v -b jar.txt localhost:9998/dashboard
```

Expected: `303 See Other` redirect to `/login` (session gone).

## 9. Duplicate registration

```bash
curl -v -c jar.txt -X POST localhost:9998/register \
  --data-urlencode 'email=dan@example.com' \
  --data-urlencode 'password=other'
```

Expected: `409 Conflict` with `email already registered`.

## 10. Bad credentials (verify forensic event)

```bash
curl -v -c jar.txt -X POST localhost:9998/login \
  --data-urlencode 'email=dan@example.com' \
  --data-urlencode 'password=wrong' -L
```

Expected: `401 Unauthorized` with `invalid credentials`.

```bash
task nats -- stream view ES_auth
```

Expected: a `UserLoginFailed` event with `"reason":"bad_credentials"` in the payload. The HTTP response does NOT reveal the reason.

## 11. Unknown email (verify forensic event)

```bash
curl -v -c jar.txt -X POST localhost:9998/login \
  --data-urlencode 'email=nobody@example.com' \
  --data-urlencode 'password=anything' -L
```

Expected: `401 Unauthorized` with `invalid credentials` (same response as bad password — no user enumeration).

```bash
task nats -- stream view ES_auth
```

Expected: a `UserLoginFailed` event with `"reason":"unknown_email"` in the payload.

## 12. View your login history (projection demo)

Log in again to get a fresh session cookie (steps 7 and 8 destroyed the
previous one):

```bash
curl -v -c jar.txt -b jar.txt -X POST localhost:9998/login \
  --data-urlencode 'email=dan@example.com' \
  --data-urlencode 'password=secret' -L
```

Then query the per-user login-history projection:

```bash
curl -s -b jar.txt localhost:9998/me/logins | jq
```

