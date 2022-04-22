from ecdsa import SigningKey, NIST521p


sk = SigningKey.generate(curve=NIST521p)
vk = sk.verifying_key
signature = sk.sign(b"message")
assert vk.verify(signature, b"message")