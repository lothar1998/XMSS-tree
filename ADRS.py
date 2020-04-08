#WATCH OUT WHICH TREE you need to use
#It would work without getters and setters, but will make it easier for us
#everything is in big endian
class ADRS:
    #init ADRS structure with bytes containing 0es
    layerAddress=bytearray(4)
    treeAddress=bytearray(8)
    typetype=bytearray(4)
    first=bytearray(4)
    second=bytearray(4)
    third=bytearray(4)
    keyAndMask=bytearray(4)
    #Types of ADDR:
        #IF typetype == 0 we get OTS Hash Address:
            #first == OTS address
            #second == chain address
            #third == hash address
        #IF typetype == 1 we get L-tree Address:
            #first == L-tree address
            #second == tree height
            #third == tree index 
        #IF typetype == 2 we get Hash Tree Address:
            #first == Padding (so only 4 bytes of zeroes)
            #second == tree height
            #third == tree index 
    #When we change typetype, we have to clear next 4 fields - setter setType() does it automatically.

    #without "self" functions won't work

    #setter of type, which have to clear next 4 fields after typetype
    def setType(self,a):
        self.typetype=(a).to_bytes(4, byteorder='big')
        self.first=bytearray(4)
        self.second=bytearray(4)
        self.third=bytearray(4)
        self.keyAndMask=bytearray(4)

    #getters (they return INTEGERS):
    def getTreeHeight(self):
        return int.from_bytes(self.second, byteorder='big')
    
    def getTreeIndex(self):
        return int.from_bytes(self.third, byteorder='big')

    #setters (they take INTEGERS):
    def setHashAddress(self,a):
        self.third=(a).to_bytes(4, byteorder='big')

    def setKeyAndMask(self,a):
        self.keyAndMask=(a).to_bytes(4, byteorder='big')

    def setChainAddress(self,a):
        self.second=(a).to_bytes(4, byteorder='big')

    def setTreeHeight(self,a):
        self.second=(a).to_bytes(4, byteorder='big')

    def setTreeIndex(self,a):
        self.third=(a).to_bytes(4, byteorder='big')

    def setOTSAddress(self,a):
        self.first=(a).to_bytes(4, byteorder='big')
     
    def setLTreeAddress(self,a):
        self.first=(a).to_bytes(4, byteorder='big')

    def setLayerAddress(self,a):
        self.layerAddress=(a).to_bytes(4, byteorder='big')

    def setTreeAddress(self,a):
        self.treeAddress=(a).to_bytes(4, byteorder='big')

#TEST
#adrs=ADRS()
#print(adrs.getTreeHeight())
#adrs.setTreeHeight(999999999)
#print(adrs.getTreeHeight())
