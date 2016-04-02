# mruby-bcrypt [![Build Status](https://travis-ci.org/baldowl/mruby-bcrypt.svg?branch=master)](https://travis-ci.org/baldowl/mruby-bcrypt) [![GitHub version](https://badge.fury.io/gh/baldowl%2Fmruby-bcrypt.svg)](https://badge.fury.io/gh/baldowl%2Fmruby-bcrypt)

OpenBSD-style Blowfish-based password hashing.

It's essentially a port of [BCrypt](https://github.com/codahale/bcrypt-ruby),
the popular Ruby gem; the API is not 100% the same, but if you don't pass it
garbage you'll receive good, compatible results.

Dependencies:

* a regular expression engine (I chose `mruby-onig-regexp`);
* either OpenSSL or, if you're compiling for a not-too-old Apple platform,
  Common Crypto (if you're compiling for an old Apple platform, tweak
  `mrbgem.rake` to link `crypto` unconditionally).

## Installation

Add the usual `conf.gem` line to `build_config.rb`:

```ruby
MRuby::Build.new do |conf|
  # ...

  conf.gem :github => 'baldowl/mruby-bcrypt'
end
```

## Examples

```ruby
> hashed_password = BCrypt::Password.create('plain text password')
 => #<BCrypt::Password:0x7f835a8248f0>
> puts hashed_password
$2b$10$J8kaghfcC2/A4gV1ZCkh9eALLr7jZNSrOG9woBaYsdDahg1iRpe3C
 => nil
> hashed_password.version
 => "2b"
> hashed_password.cost
 => 10
> hashed_password.salt
 => "$2b$10$J8kaghfcC2/A4gV1ZCkh9e"
> hashed_password.checksum
 => "ALLr7jZNSrOG9woBaYsdDahg1iRpe3C"
> hashed_password == 'plain text password'
 => true
> hashed_password == 'clearly not my password'
 => false
```

## License

This code is released under the MIT License: see LICENSE file.

C implementation of the BCrypt algorithm by Solar Designer and placed in the
public domain. You can find the original code of `crypt_blowfish-1.3`,
downloaded from http://www.openwall.com/crypt/ on 2015-02-28, in
`src/crypt_blowfish`.

BCrypt Ruby gem has been written by Coda Hale <coda.hale@gmail.com> and
released under the MIT License.
