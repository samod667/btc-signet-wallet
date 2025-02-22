# Signet Wallet Project

The goal of this project is to write a simple wallet over two weeks and use it
to interact with a custom signet network provided by the administrator.

## Simplify

To reduce the scope of this project the wallet will be very limited:
- No separate change addresses: one descriptor is used for all internal and external addressees.
- No [VarInt](https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer):
all vectors will be under 255 bytes in length and always require one single
byte to indicate length.
- All sending and receiving addresses will be [`p2wpkh`](https://en.bitcoin.it/wiki/BIP_0141#P2WPKH)
    - Except one [`p2wsh`](https://en.bitcoin.it/wiki/BIP_0141#P2WSH) multisig which is the goal of the week 2 assignment
- Fees can be hard-coded by value, no estimation is necessary.
- Transactions you create will always have exactly 1 input and 2 outputs.
- Don't worry about invalid keys (probabilty is less than 1 in 2<sup>127</sup>)
- Other constants:
    - All transactions will be version 2 (little-endian encoded as `\x02\x00\x00\x00`)
    - All input sequences will be `0xffffffff`
    - All transaction locktimes will be `0x00000000`
    - All input scriptSigs will be `0x00` (because we are only concerned with segregated witness inputs)
    - All sighash flags will be `SIGHASH_ALL` which is `0x01` in signatures and little-endian encoded as `\x01\x00\x00\x00` in transaction commitments



</details>
