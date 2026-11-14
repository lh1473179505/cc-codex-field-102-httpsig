"""sign and verify — not implemented in the initial snapshot."""


class NotImplementedEngine(NotImplementedError):
    pass


def verify(message, keys, policy):
    raise NotImplementedEngine("httpsig.verify is not implemented")


def sign(message, keys, policy):
    raise NotImplementedEngine("httpsig.sign is not implemented")
