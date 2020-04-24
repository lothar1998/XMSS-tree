
class SigWithAuthPath:
    def __init__(self, sig_ots, auth):
        self.sig_ots = sig_ots
        self.auth = auth

    def getSig_ots(self):
        return self.sig_ots

    def getAuth(self):
        return self.auth