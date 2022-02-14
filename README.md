<p align="center">
  <img src="./images/pushtx.jpg" alt="logo" height="200"/>
</p>
<ul/>
Go Library for building OP_PUSH_TX Transactions

## Note
The library builds transactions utilizing the [optimized OP_PUSH_TX](https://xiaohuiliu.medium.com/optimal-op-push-tx-ded54990c76f) script which requires low-s value in when constructing the preimage. NewOpPushTransaction function malleates nLockTime to acheive low-s. Regular OP_PUSH_TX will be added to the library in a future update.
