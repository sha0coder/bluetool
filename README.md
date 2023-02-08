# Bluetool

bluetooth tool for pentesting.


```bash
~/s/bluetool ❯❯❯ ./bluetool
bluetool v0.20 usage:

 ./bluetool [mode] (interface) (target)
examples:
 ./bluetool i                                 enum bluetooth local interfaces
 ./bluetool s 0                               scan devices throught the interface 0
 ./bluetool e 0                               scan devices throught the interface 0
 ./bluetool h 0                               scan hidden devices (very slow)
 ./bluetool r 0 11:22:33:44:55:66             rfcomm channel scan (noisy)
 ./bluetool l 0 11:22:33:44:55:66             l2cap psm scan
 ./bluetool p 0 11:22:33:44:55:66 psm data    l2cap psm send data
 ./bluetool q 0 11:22:33:44:55:66 psm data imtu omtu flushto dcid flags    l2cap psm send req
 ./bluetool c 0 11:22:33:44:55:66             low level command fuzzer
 ./bluetool u 0 11:22:33:44:55:66             services uuid scan
```
