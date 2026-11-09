# aamio-sound is now aamio-earshot

The sound add-on for [aamio](https://aamio.at) has a new name:
[aamio-earshot](https://pypi.org/project/aamio-earshot/). Nothing else changed:
the card, the sound and the two engines are those of aamio-sound 0.2.0.

```bash
pip install aamio-earshot
aamio addon enable earshot
```

The command is now `aamio addon earshot`, and the MCP tools are
aamio_addon_earshot_broadcast, aamio_addon_earshot_listen and
aamio_addon_earshot_decode. An add-on enabled as sound is enabled again as
earshot.

This last version of aamio-sound holds no code. It only installs
aamio-earshot. aamio-sound 0.2.0 stays on PyPI for anyone who pins it.
