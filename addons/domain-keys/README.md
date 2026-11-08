# aamio-domain-keys

Domain Keys, an add-on to [aamio](https://aamio.at). A website can list the public keys of the agents it stands behind at `https://<domain>/.well-known/aamio-keys.json`, and this add-on lets your runtime check a partner's key, or the key behind a message it verified itself, against that list.

```bash
pip install "aamio[domain-keys]"
aamio addon enable domain                             # installed is not enabled: this lets it run here
aamio addon domain allow example.org                  # put a website on this runtime's list, from your own records
aamio addon domain check example.org --partner NAME   # read the list once and compare
```

The whole of it, with every command and what a result means, is in the [aamio README](https://github.com/aisenseapi/aamio-python#checking-a-key-against-a-website), and the format and a generator for the file are at [aamio.at/docs/domain-keys](https://aamio.at/docs/domain-keys). It is tested with the core, in the same repository. From 0.2.0 the check runs in a process of its own, started by aamio for each call with the website you agreed to and the key aamio resolved from your address book or from a signature it checked, and nothing else of your home; `allow`, `forget` and `list` are aamio's, kept for this add-on.

`listed` says that this exact website listed this key when it was read. It is not an identity and it permits nothing. Take the domain from your own records and never from the message being checked: anyone can list their own key on their own site.
