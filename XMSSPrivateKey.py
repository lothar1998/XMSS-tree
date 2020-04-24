class XMSSPrivateKey:

    def __init__(self):
        self.wots_private_keys = None
        self.idx = None
        self.SK_PRF = None
        self.root_value = None
        self.SEED = None

    def getSEED(self):
        return self.SEED

    def setSEED(self, value):
        self.SEED = value

    def getWOTS_SK(self, i):
        return self.wots_private_keys[i]

    def setWOTS_SK(self, list_of_wots_sk):
        self.wots_private_keys = list_of_wots_sk

    def setIdx(self, value):
        self.idx = value

    def getIdx(self):
        return self.idx

    def getSK_PRF(self):
        return self.SK_PRF

    def setSK_PRF(self, value):
        self.SK_PRF = value

    def getRoot(self):
        return self.root_value

    def setRoot(self, value):
        self.root_value = value
