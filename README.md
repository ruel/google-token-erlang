# Google ID Token Verifier - Erlang

[![Build Status](https://travis-ci.org/ruel/google-token-erlang.svg?branch=master)](https://travis-ci.org/ruel/google-token-erlang) [![Hex.pm](https://img.shields.io/hexpm/v/google_token.svg)](https://hex.pm/packages/google_token)

An Erlang application that verifies the integrity of Google ID tokens
in accordance with [Google's criterias](https://developers.google.com/identity/sign-in/web/backend-auth).

Google ID tokens are JWT web tokens passed by clients applications who
authenicated to [Google Identity Platform](https://developers.google.com/identity/protocols/OpenIDConnect)

## OTP Version

**Required**: OTP 18 and later

## Setup

This application can be downloaded as a dependency from [Hex](https://hex.pm/packages/google_token)

```erlang
{deps, [
  {google_token, "1.0.3"}
]}. 
```

Start **google_token** in your application's `.app.src` file

```erlang
{applications, [
  kernel,
  stdlib,
  crypto,
  ssl,
  inets,
  google_token  
]}.
```

> **NOTE**: The applications **crypto**, **ssl**, and **inets** must be started
first

## Usage

Once started, **google_token** can be used by calling either `validate/1` or
`validate/2`

```erlang
IdToken = <<"eyJhbGciOiJSUzI1NiIsImtpZCI6IjcxMjY3OWMzMzVmMWQyZGIxM2FkZTQ0N2NlYjY2NThkM2QwZWExZWIifQ....">>,
{valid, Claims} = google_token:validate(IdToken).
```

It's necessary to check the `aud` claim against your own client ID. You can
do this manually by yourself, or you can pass a list of IDs as the second
parameter of `validate/2`

```erlang
IdToken = <<"eyJhbGciOiJSUzI1NiIsImtpZCI6IjcxMjY3OWMzMzVmMWQyZGIxM2FkZTQ0N2NlYjY2NThkM2QwZWExZWIifQ....">>,
Ids = [<<"...apps.googleusercontent.com">>],
{valid, Claims} = google_token:validate(IdToken, Ids).
```

Implementation based on: https://developers.google.com/identity/sign-in/web/backend-auth
