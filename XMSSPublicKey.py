class XMSSPublicKey:

    def __init__(self):
        self.OID = None
        self.root_value = None
        self.SEED = None

    def getOID(self):
        return self.OID

    def setOID(self, value):
        self.OID = value

    def getSEED(self):
        return self.SEED

    def setSEED(self, value):
        self.SEED = value

    def getRoot(self):
        return self.root_value

    def setRoot(self, value):
        self.root_value = value