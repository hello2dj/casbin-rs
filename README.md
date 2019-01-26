casbin-rs
====

casbin-rs a Rust implementation of the authorisation library [Casbin](https://casbin.org). It 
provides support for enforcing authorization based on various 
[access control models](https://en.wikipedia.org/wiki/Computer_security_model).

**DISCLAIMER:** This library is still under development (Work in Progress) and it is not
production-ready. DO NOT USE it in production environment.

## Implementation status

Implemented features

- Basic rule checking 
- RBAC model
- File Adapter
- Builtin operators

Incomplete or missing features:

- Support of domains (incomplete)
- custom operators
- Filtered policy support
- Priority rules
- Autosave 
- Logging
- Watcher
- in operator


## License

This project is licensed under the [Apache 2.0 license](LICENSE).
