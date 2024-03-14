Planned
=======

- [ ] performance measurements: counting number of requests for different operations (graphing results)
- [ ] **make output encryption size uniform: messages should not be distinguishable by encrypted length**
- [ ] timed messages that delete after some time (sort of; this is a convenience handled by the client)
- [ ] automatic generation of input and test data
- [x] hide usernames: no usernames should be visible to server operator

Not Planned
===========

- delete other people's messages: use a joint shared key to access chats, either user may delete their half of key to revoke access to the whole chat for both users
  - this seems to work conceptually, but would require finding a new cryptography scheme(s) and replacing a large portion of the code
- disturbing timestamps of redacted messages (and measuring privacy impact): this seems like it would be relatively low-impact in general, so it's low-priority


