# DirtyDecrypt / DirtyCBC

DirtyDecrypt, also known as DirtyCBC, is a variant of CopyFail / DirtyFrag / Fragnesia. We found and reported this on [May 9, 2026](https://x.com/v12sec/status/2053029838995263854), but was informed it was a duplicate by the maintainers. We're releasing it now since it's patched on mainline. It's a rxgk pagecache write due to missing COW guard in rxgk_decrypt_skb. See `poc.c` for more details.

DirtyDecrypt was discovered autonomously with [V12](https://v12.sh) by Aaron Esau of the [V12 security team](https://x.com/v12sec).

> Want to find issues like this in your own code? Try V12 at [v12.sh](https://v12.sh).

```
$ sha256sum ./poc.c
8054e424466ed2c353b94fb25643e17bef50b31be95038e1c700156357e2d74b  ./poc.c
```
