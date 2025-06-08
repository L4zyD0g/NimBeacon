# NimBeacon

NimBeacon is a CobaltStrike stageless beacon implemented in Nim.

It have been tested on Windows 11 and Cobalt Strike 4.5.

Any contributions are welcome.

*This project is for learning purpose only. DO NOT USE IT ILLEGALLY.*

## Compile

```
# install dependencies
nimble install winim zippy nimcrypto checksums

# compile release version
nim c -d:release -d:ssl beacon.nim
# compile debug version
nim c -d:ssl beacon.nim
```

## Thanks
Thanks to the following projects and articals:
- [geacon_plus](https://github.com/Z3ratu1/geacon_plus)
- [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim)
- [[原创]魔改CobaltStrike：命由己造（上）](https://bbs.kanxue.com/thread-267848.htm)
- [CobaltStrike beacon二开指南](https://blog.z3ratu1.top/CobaltStrike%20beacon%E4%BA%8C%E5%BC%80%E6%8C%87%E5%8D%97.html)
- [CS DNS beacon二次开发指北](https://blog.z3ratu1.top/CS%20DNS%20beacon%E4%BA%8C%E6%AC%A1%E5%BC%80%E5%8F%91%E6%8C%87%E5%8C%97.html)
- [CobaltStrike逆向学习系列](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=MzkxMTMxMjI2OQ==&action=getalbum&album_id=2174670809724747778&scene=173&from_msgid=2247483983&from_itemidx=1&count=3&nolastread=1#wechat_redirect)

## TODO
- [ ] Refactor code

Compatible with Cobalt Strike 4.5:
- [ ] Implement more commands
- [x] Support DNS
- [ ] Support linux and macOS

Some new features may require patches in Cobalt Strike
- [ ] Remove checksum8 and others to evade scanning
- [ ] Implement new commands
- [ ] Implement new protocols(like smtp/github?)