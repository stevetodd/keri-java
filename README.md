# KERI for Java

keri-java is a Java-based implementation of
the [Key Event Receipt Infrastructure specification](https://github.com/decentralized-identity/keri)
.

## Status

**keri-java is not ready for production usage.** This project is under heavy development and
provides no guarantees of a stable API for application developers. Further, the specification is
also under heavy development.

Below describes the current capabilities of keri-java:

**Identifiers:**

- [x] Create Basic Identifiers
- [x] Create Self-Addressing Identifiers
- [x] Create Self-Signing Identifiers
- [x] Rotate non-Basic Identifiers
- [x] Record interactions in the event log
- [x] Simple signing thresholds
- [x] Multi-signature identifiers
- [x] Weighted signing threshold
- [ ] Delegation

**Logs**

- [x] Serialization
- [x] Verification
  - [ ] Recovery
  - [ ] Delegation Seals
  - [ ] Out of Order Events
- [ ] \(In Progress) Storage

**Private/Direct Mode**

- [x] Keri Protocol Server and Client
- [x] keripy/eve interoperability
- [x] keripy/bob interoperability
- [x] keripy/sam interoperability

**Public/Indirect Mode**

Most of the items here have not yet been defined in the specification.

- [ ] Witness Gossip Capabilities
- [ ] Query API
- [ ] Verifier Logic (Watcher, Juror, Judge, etc.)

## Downloads

| | Linux | macOS | Widows |
|---|---|---|---|
| Controller CLI | intel \| arm | intel \| arm | intel \| arm |
| Publisher Node | intel \| arm | intel \| arm | intel \| arm |
| Resolver Node  | intel \| arm | intel \| arm | intel \| arm |

All builds are 64-bit.

## Maven Coordinates

**Lookup Module**

The lookup module provides applications the ability to obtain current verification keys and state
information about an identifier.

```xml
<dependency>
  <groupId>foundation.identitity.jkeri</groupId>
  <artifactId>lookup</artifactId>
  <version>[VERSION]</version>
</dependency>
```

**Controller Module**

The controller modules provides applications the ability to create and manage KERI identifiers.

```xml
<dependency>
  <groupId>foundation.identitity.jkeri</groupId>
  <artifactId>controller</artifactId>
  <version>[VERSION]</version>
</dependency>
```

## Getting Started

See each individual component's README for more information about getting started.

**[Lookup Client Library](lookup)**<br/>
Obtains public key information for an identifier.

**[Controller Client Library](controller)**<br/>
Provides for the management of an identifier.

**[CLI Controller](controller-cli)**<br/>
Provides for the management of an identifier.

**[Witness/Publisher Node](publisher-daemon)**<br/>
A witness node.

**[Verifier/Resolver Node](resovler-daemon)**<br/>
A combination verifier/resolver.

**[Core](core)**<br/>
Code that is common to each of the components above.
