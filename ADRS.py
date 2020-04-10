# WATCH OUT WHICH TREE you need to use
# It would work without getters and setters, but will make it easier for us
# everything is in big endian

class ADRS:
    # init ADRS structure with bytes containing 0es
    def __init__(self):
        self.layerAddress = bytes(4)
        self.treeAddress = bytes(8)
        self.type = bytes(4)

        self.first_word = bytes(4)
        self.second_word = bytes(4)
        self.third_word = bytes(4)

        self.keyAndMask = bytes(4)

    # Types of ADDR:
    # IF typetype == 0 we get OTS Hash Address:
    # first == OTS address
    # second == chain address
    # third == hash address
    # IF typetype == 1 we get L-tree Address:
    # first == L-tree address
    # second == tree height
    # third == tree index
    # IF typetype == 2 we get Hash Tree Address:
    # first == Padding (so only 4 bytes of zeroes)
    # second == tree height
    # third == tree index
    # When we change typetype, we have to clear next 4 fields - setter setType() does it automatically.

    # without "self" functions won't work

    # setter of type, which have to clear next 4 fields after typetype
    def setType(self, type):
        self.type = type.to_bytes(4, byteorder='big')
        self.first_word = bytearray(4)
        self.second_word = bytearray(4)
        self.third_word = bytearray(4)
        self.keyAndMask = bytearray(4)

    # getters (they return INTEGERS):
    def getTreeHeight(self):
        return self.second_word

    def getTreeIndex(self):
        return self.third_word

    # setters (they take INTEGERS):
    def setHashAddress(self, value):
        self.third_word = value.to_bytes(4, byteorder='big')

    def setKeyAndMask(self, value):
        self.keyAndMask = value.to_bytes(4, byteorder='big')

    def setChainAddress(self, value):
        self.second = value.to_bytes(4, byteorder='big')

    def setTreeHeight(self, value):
        self.second_word = value.to_bytes(4, byteorder='big')

    def setTreeIndex(self, value):
        self.third_word = value.to_bytes(4, byteorder='big')

    def setOTSAddress(self, value):
        self.first = value.to_bytes(4, byteorder='big')

    def setLTreeAddress(self, value):
        self.first = value.to_bytes(4, byteorder='big')

    def setLayerAddress(self, value):
        self.layerAddress = value.to_bytes(4, byteorder='big')

    def setTreeAddress(self, value):
        self.treeAddress = value.to_bytes(4, byteorder='big')




